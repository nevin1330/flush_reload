// created by nevin
// Shared GnuPG configuration for Flush+Reload Attack Implementation
// Based on: "Flush+Reload: A High Resolution, Low Noise, L3 Cache Side-Channel Attack"
// Yuval Yarom and Katrina Falkner, USENIX Security 2014

#ifndef GNUPG_CONFIG_H
#define GNUPG_CONFIG_H

// GnuPG 1.4.13 installation path (as used in the paper)
#define GNUPG_INSTALL_PATH "/home/ev/genkin/sep_4/gnupg-install"
#define GNUPG_BINARY_PATH GNUPG_INSTALL_PATH "/bin/gpg"

// GnuPG version and target information
#define GNUPG_VERSION "1.4.13"
#define GNUPG_TARGET_DESCRIPTION "GnuPG 1.4.13 RSA Implementation"

#endif // GNUPG_CONFIG_H
