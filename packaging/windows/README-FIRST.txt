bacnet-health {VERSION} for Windows (64-bit)
=============================================

bacnet-health checks the health of a BACnet/IP building network. It is read-only: it never writes to any
device. It only sends discovery (Who-Is) and read requests, at a limited rate, after you have confirmed the
network interface and the plan.


1. Install
----------

Nothing to install. Do not run it from inside the zip file.

  a) Right-click the zip file > "Extract All..." and choose a folder, for example your Desktop or a USB drive.
  b) Open the extracted "bacnet-health" folder.
  c) Double-click bacnet-health.exe.

Keep all files of the folder together. The program needs the "_internal" folder next to the exe.
Windows 10 or 11 (64-bit) is required. No administrator rights are needed.


2. "Windows protected your PC" (SmartScreen)
--------------------------------------------

This early release is not yet digitally signed, so Windows may show a blue "Windows protected your PC" box
the first time you start it:

  - Click "More info".
  - Check that the app name is bacnet-health.exe.
  - Click "Run anyway".

Only do this for a copy you downloaded from the official release page, and compare the SHA-256 checksum
(the .sha256 file published next to the zip) if you can:

  PowerShell:  Get-FileHash .\bacnet-health-{VERSION}-win-x64.zip -Algorithm SHA256


3. Windows Firewall prompt
--------------------------

The first time you run a health check or listen on the network, Windows Defender Firewall may ask
"Do you want to allow bacnet-health to communicate on these networks?" (it may need an administrator to
approve it).

  - Tick "Private networks" (and "Domain networks" if it is shown), then click "Allow".
  - Do NOT click "Cancel". Cancel tells Windows to block replies to bacnet-health. Discovery will then find
    no devices, and Windows will not ask again. If that happened, ask your IT team to remove the block rule
    for bacnet-health (Windows Defender Firewall > Allow an app through firewall), or to allow inbound
    UDP 47808 for bacnet-health.exe.

The pre-flight screen of bacnet-health shows whether the firewall is likely to block replies.
Analysing a capture file and the demo never use the network and never trigger this prompt.


4. What is in this folder
-------------------------

  bacnet-health.exe        The application (double-click this).
  bacnet-health-cli.exe    Command-line version for advanced users. Open a terminal in this folder and run
                           "bacnet-health-cli --help".
  _internal\               Files the program needs (Python runtime, Qt libraries). Do not delete.
  THIRD_PARTY_NOTICES.md   Licences of the third-party components (Qt/PySide6 under LGPL-3.0, Python).
  licenses\                Full licence texts.

bacnet-health itself is released under the MIT licence.


5. Removing it
--------------

Delete the folder. bacnet-health does not install anything and does not change system settings.
Your reports stay wherever you saved them.


Project page: https://github.com/lns-hk/bacnet-health
