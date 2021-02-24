# TQ-pre-jailbreak

A **PRE**-jailbreak for iOS 14.0 ~ iOS 14.3 on all devices.

Generally speaking, jailbreak starts from an arbitrary kernel r/w vulnerability, so I name it pre-jailbreak. Actually, CVE-2021-1782(cicuta\_virosa) is the pre-jailbreak thing.

Implemented an arbitrary r/w primitive based on [cicuta\_virosa](https://github.com/ModernPwner/cicuta_virosa). Useful to security researchers, and jailbreak developers.

# Warranty

**Use it on your own risk**. I build it for security researchers only. **MEAN NOTHING** to normal user.

**DO NOT RUN IT** on you main device. I can not promise **WHAT WILL HAPPEN!**

# Current state

- [x] stable kernel r/w primitives
- [x] ~~amfid bypass~~ Implement it by yourself. Bad guys could use this to distribute malicious code directly.

Tested on iPhone 12 pro (**iOS 14.3**).

Tested on iPhone 11 (**iOS 14.0**).

Tested on iPhone 6s (**iOS 14.0**). Maybe helpful to A11 devices. I note that checkra1n said "Limited support for A11 devices on iOS 14.x".

For other devices/iOSs, add kernel offsets yourself in k\_offsets.c

# Credits

- @ModernPwner: CVE-2021-1782, exploitation technique
- Brandon Azad (@\_bazad): Almost everything starts from oob\_timestamp
- @chenliang0817: paper "Exploiting IOSurface 0"
- Jailbreak knowledge from unc0ver
- [#FreeTheSandbox](https://github.com/ZecOps/FreeTheSandbox_LPE_POC_13.7): post-exploit tech & binpack
- etc.

# License

GPL-3.0 License

inherited from cicuta\_virosa

# Misc

my twitter [@pattern\_F\_](https://twitter.com/pattern_F_)

English is hard for me... I'm learning it.

英语太难了...
