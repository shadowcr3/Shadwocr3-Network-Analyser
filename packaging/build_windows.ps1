# Build a Windows one-folder distribution. Run from the project root.
# NOT verified by the automated test suite: smoke-test the resulting exe before releasing.
$ErrorActionPreference = "Stop"
python -m pip install -e ".[gui,dev]"
python -m pytest -q
python -m PyInstaller --noconfirm --clean --windowed --name Shadowcr3NetworkAnalyzer --paths src packaging\launch_gui.py
Compress-Archive -Path dist\Shadowcr3NetworkAnalyzer -DestinationPath dist\Shadowcr3NetworkAnalyzer-0.1.0-win64.zip -Force
Get-FileHash dist\Shadowcr3NetworkAnalyzer-0.1.0-win64.zip -Algorithm SHA256 | Format-List
Write-Host "Nmap is not bundled: install it separately (https://nmap.org/download)."
