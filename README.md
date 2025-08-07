**Forcable purge windows apps from your system**
> **Warning**: This program modifies Windows and registry settings. Create a system restore point before use.  
> An automatic restore point is attempted (Windows limits 1 every 24 hours).  
>  
> **Disclaimer**: AppExorcist is provided "as is" without warranty of any kind, express or implied, including but not limited to fitness for a particular purpose.  
> Use at your own risk. The developers are not liable for any damages or data loss caused by this program.  

<br>

[Download Link](https://github.com/ShadowWhisperer/AppExorcist/blob/main/AppExorcist.exe?raw=true)


## System Requirements
- **Supported OS**: Windows 8, 10, 11 (64-bit only)

## Features
- **App Removal**: Removes apps and associated remnants, though not 100% of registry keys/files due to naming variations, Windows Updates, etc.
- **Database Management**: Automatically updates app list database on startup. Manual update:
  - Download: [apps.json](https://raw.githubusercontent.com/ShadowWhisperer/AppExorcist/main/Source/apps.json)
  - Place apps.json in: `C:\ProgramData\ShadowWhisperer\Apps\database_new.json`
- **Remnants Scan**: Searches for leftover app files/keys based on `Source/apps.json`. Takes a long time and will show undeletable items.
- **Log**: Saves uninstall details to `C:\ProgramData\ShadowWhisperer\Apps\uninstall.log`
- **Startup Checks**: Verifies services (PcaSvc, AppXSvc, camsvc) and registry keys to prevent app re-installation.

## How It Works
- **Startup**: Checks for conflicts or issues, fixing them if needed. A brief GUI may appear on slower hardware.
- **Database**: Builds `C:\ProgramData\ShadowWhisperer\Apps\database.json` on startup for installed apps, refreshing only when needed.
- **App List**: Hides critical apps (e.g., `Microsoft.Windows.DevicesFlowHost`) to prevent system issues. See `Source/apps.json` for hidden apps (`"hide": "yes"`).
- **App Removal**: Searches system for files/registry keys to delete, using app-specific data from `Source/apps.json` (e.g., `Microsoft.Print3D` context menu keys).

## apps.json
- `name`: Publisher-given app name (e.g., `SAMSUNGELECTRONICSCO.LTD.Bixby`)
- `info`: Display name (e.g., `[App] Bixby AI`)
- `issues`: Problems caused by removal (e.g., `Breaks Windows Store Apps`)
- `hide`: Hide from viewable list (`yes`/`no`)
- `native`: Part of clean Windows install (`yes`/`no`)
- `bloat`: Non-essential software (`yes`/`no`)

## Notes
- **Desktop Icon Flicker**: Caused by clearing installed app list cache during database rebuild. See `rebuild_database` in source code.
- **Windows 11 Reboot**: Required to clear apps from list due to differences in app management compared to Windows 10.
- **Unknown Apps**: Apps with `?` in `Info` or `Issues` are not in the database or unverified for safe removal. Research before removing.
- **Bloat vs. Native**: 
  - **Bloat**: Non-essential, third-party software.
  - **Native**: Built into a clean Windows install.
- **Remnants Scan**: May take a long time to run or log entries. (It has to find them first)
- **Comparison to RevoUninstaller**: AppExorcist searches dynamically for remnants, unlike Revo’s predefined lists. It’s free, with no animations or PowerShell popups.

## Limitations
- **Incomplete Removal**: Some registry keys/files may persist due to system constraints.
- **Hidden Apps**: Critical apps are hidden to avoid breaking system functionality. Remove ? apps at your own risk.


https://github.com/ShadowWhisperer/AppExorcist/assets/61057625/864408be-c763-465b-bf0d-2fc0a1db03a4
