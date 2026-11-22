# Attribution — web category lists

MinControl's web-category filtering (NetGuard `CategoryUpdater`) downloads domain lists from the
**UT1 blacklists** maintained by Fabrice Prigent, Université Toulouse Capitole (DSI):

- Site: https://dsi.ut-capitole.fr/blacklists/
- Archives: `https://dsi.ut-capitole.fr/blacklists/download/<list>.tar.gz` (contains `<list>/domains`)
- License: **Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)**,
  https://creativecommons.org/licenses/by-sa/4.0/

The lists are downloaded by the MinControl service on each device and transformed locally (lower-cased, IPs and
invalid entries removed, stored as sorted 64-bit XxHash64 values in `%ProgramData%\MinControl\categories\*.bin`).
They are not redistributed with MinControl. If derived lists are ever shipped, they must be shared under
CC BY-SA 4.0 with this attribution.

| MinControl category | UT1 list(s) |
|---|---|
| adult | adult |
| gambling | gambling |
| proxy-vpn | vpn, redirector |
| games | games |
| social | social_networks |
| video | audio-video |
| violence | agressif |
| drugs | drogue |
| dating | dating |
| malware | phishing (UT1 `malware` is an alias of `phishing`) |
