# Sand Box Dashboard

A small Windows dashboard that shows what a program changes on a machine. It takes a snapshot of the system before you run or install a file, records what happens while it runs, takes a second snapshot afterwards, and produces a PDF report of the differences.

It is meant for a dedicated analysis VM, for example to check software before it is allowed onto a LAN.

![Dashboard after both shots and Compare](docs/images/dashboard.png)

## What it checks

Taken in both snapshots and compared:

| Check | What is compared |
|---|---|
| Registry | Keys and values added, deleted and modified in `HKEY_LOCAL_MACHINE` and `HKEY_USERS` |
| Files | Files and folders added, deleted and modified in the watched folders, with SHA-256 for new files |
| CurrPorts | Open ports and the program that owns them |
| Netstat | Connections and listening ports |
| Processes | Running programs |
| Autoruns | Everything set to start automatically |
| Services | Services added, removed or changed |
| Scheduled tasks | Tasks added, removed or changed |

Recorded while the file runs:

| Recording | What is reported |
|---|---|
| Procmon | Processes started, files written and deleted, registry values set, network connections by process |
| Packet capture | Domain names looked up, host names in web traffic, TCP and UDP destinations |

## Requirements

- Windows 10 or 11 (64-bit), in a virtual machine
- Python 3.8 or newer from [python.org](https://www.python.org/downloads/), installed with "tcl/tk and IDLE" ticked
- An Administrator account

No Python packages are needed; the script uses only the standard library. It works without an internet connection.

### Third-party tools

These are not included in this repository. Download them from their publishers and copy the files into `C:\SandboxTools`:

| File | From |
|---|---|
| `cports.exe` | NirSoft CurrPorts |
| `autorunsc64.exe` | Microsoft Sysinternals Autoruns (the command-line program inside the Autoruns zip) |
| `Procmon64.exe` | Microsoft Sysinternals Process Monitor |

A tool that is missing is skipped; the other checks still run. The Settings window shows which tools were found.

## Setup

1. Install Python and check it: `py -c "import tkinter; print('tk ok')"`
2. Create `C:\SandboxTools` and copy in the three tools above.
3. Copy `sandbox_dashboard.py` and `run_sandbox.bat` into `C:\SandboxTools`.
4. Take a snapshot of the VM in your hypervisor, so you can roll back after each test.

## Use

Start the dashboard by double-clicking `run_sandbox.bat`, or run `py sandbox_dashboard.py` from an Administrator command prompt.

1. Type a project name and click **Create a project**. A folder with that name is created on the Desktop.
2. Click **Browse for PE / MSI** and choose the file to test.
3. Click **Run Sand Box Tool for 1st shot** and wait for the ticks.
4. Click **Install/Run**. The recording starts, then the file starts. Finish the install or let the program run.
5. Click **Run Sand Box Tool for 2nd shot**. The recording stops and the second snapshot is taken.
6. Click **Compare**.
7. Click **Generate Report**. The PDF opens when it is ready.

![Dashboard while recording](docs/images/dashboard_recording.png)

## Output

Everything for one test is kept in `Desktop\<project name>\`:

```
project.json        file tested, SHA-256, times
Before\             results of the 1st shot
After\              results of the 2nd shot
Live\               Procmon recording (CSV), packet capture (pcapng), DNS names
Compare\            the differences, including full lists
<name>_Report.pdf   the report
```

A sample report built from made-up data is in [docs/sample_report.pdf](docs/sample_report.pdf).

![First page of the report](docs/images/report_page1.png)

## Settings

Click **Settings** on the dashboard to change the sandbox title, organisation name, analyst name, report logo (PNG or JPG), tools folder, watched folders, recording options and the number of lines per category in the report. Settings are saved in `sandbox_settings.json` next to the script.

![Settings window](docs/images/settings.png)

## Things to know

- **Background noise.** Windows changes registry values, cache files and connections on its own. These appear in the report next to the changes made by the tested file.
- **Disk space.** Procmon recordings grow by roughly a few hundred MB per minute. Keep several GB free and take the 2nd shot soon after the install finishes.
- **DNS cache.** Install/Run clears the Windows DNS cache so the names listed afterwards belong to the test.
- **Watched folders.** Files created outside the watched folders are not listed in the file check.
- **Report text.** The PDF prints English and Western European letters; other scripts are printed as `?`.

More detail is in [docs/how-it-works.md](docs/how-it-works.md).

## Safety

Running a file from the dashboard really runs it on that machine. Use a virtual machine that holds nothing you care about, keep it off your production network when testing files you do not trust, and roll back to a clean snapshot after each test. Only test software you are permitted to test.

## Status

The eight snapshot checks, comparison, PDF report and packet capture have been run on Windows 11. The Procmon recording and the Settings window have been tested with sample data but not yet confirmed on Windows.
