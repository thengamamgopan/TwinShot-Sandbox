# How it works

The software compares two pictures of the machine: one taken before the tested file runs and one after. Whatever differs between them is what happened in between, and a recording made while the file runs fills in the detail.

## What each button does

### 1. Create a project

Makes a folder on the Desktop with the project name. Everything for that test is stored there, so each test is kept separate.

### 2. Browse for PE / MSI

Remembers which file you want to test. Nothing runs yet.

### 3. Run Sand Box Tool for 1st shot

Runs eight checks one after another and saves each result in the `Before` folder. A tick appears as each one finishes.

| Check | What it records | How |
|---|---|---|
| Regshot (registry) | Every registry key and value in `HKEY_LOCAL_MACHINE` and `HKEY_USERS` | Python reads the registry directly |
| Files | Path, size and last-modified time of every file in the watched folders | Python walks the folders |
| CC port | Open ports and which program owns them | `cports.exe` |
| Netstat | Open connections and listening ports | Windows `netstat` |
| Process explore | Running programs: name, path, command line | Windows process list via PowerShell |
| Auto Run | Everything set to start automatically | `autorunsc64.exe` |
| Services | All services, their state and start type | Windows service list via PowerShell |
| Schedule task | All scheduled tasks and what they run | Windows task list via PowerShell |

Regshot and Process Explorer themselves are not used, because they can only be operated by clicking in their windows. The script reads the same information from Windows directly.

### 4. Install/Run

1. Calculates the file's SHA-256 fingerprint and size for the report.
2. Clears the Windows DNS cache, so names looked up afterwards belong to this test.
3. Starts the recordings: the packet capture (`pktmon`, built into Windows), and Procmon if it is in the tools folder.
4. Starts the file. An `.msi` is opened with the Windows installer; an `.exe` is run directly.

### 5. Run Sand Box Tool for 2nd shot

1. Stops the recordings first, so the checks themselves are not recorded.
2. Runs the same eight checks again and saves them in the `After` folder.
3. Converts the recordings into readable files (`procmon.csv`, `network.pcapng`).

### 6. Compare

Reads `Before` and `After` and works out the differences, then reads the recordings.

- **Registry and files:** both snapshots are written in the same sorted order, so they are read side by side. A line only in `Before` is "deleted", a line only in `After` is "added", and a line in both with different data is "modified".
- **Ports, connections, processes, auto-run entries:** each is treated as a list. Items only in the second list are "added"; items only in the first are "removed". Processes are matched by name, path and command line, not by process number, because the number changes every time a program starts.
- **Services and tasks:** matched by name, then their settings are compared, which is how "changed" is found.
- **Live activity:** reads the Procmon recording and lists programs started, files written or deleted, registry values set, and connections made. File and registry activity is listed for programs that started during the recording; network activity is listed for every program.
- **Network activity:** reads the DNS cache and the packet capture and lists domain names, host names and addresses contacted.

### 7. Generate Report

Builds the PDF: organisation, file details and times at the top, the summary table, then one section per check listing every item. Each category shows up to 300 items (changeable in Settings); the full lists are in the `Compare` folder.

## Reading the summary table

| Column | Meaning |
|---|---|
| Added / new | Present after the run, but not before |
| Removed | Present before, gone after |
| Changed | Present both times, but with a different value |

## Limits

- **Background noise:** Windows changes registry values, cache files and connections on its own, and those appear in the results alongside the tested file's changes.
- **Two moments in time:** the eight checks only see the state at each shot. Something that appears and disappears in between is caught only by the live recording.
- **Watched folders only:** files created outside the watched folders are not listed in the file check.
- **Protected registry areas:** a few areas Windows locks even for administrators, such as the password store, cannot be read.
- **Long registry values:** values over 200 characters are shortened in the lists, with a fingerprint so a change is still detected.
- **Host names in encrypted traffic:** a host name is listed only when it can be read from the first packet of the connection.
