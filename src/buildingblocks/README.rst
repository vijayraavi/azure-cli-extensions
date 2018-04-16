Developer Setup
==============================

Prerequisites
1. pip install knack
2. pip install virtualenv
3. pip install azure.cli.core

1.  Clone repo!

2.  Setup a virtual environment:  python -m venv <path_under_project>
  ex:  python -m venv c:\azbb-port\env
  NOTE:  The "env" name is important because the dev_activate.bat and dev_deactivate.bat script use it!

3.  Run this to get the Python SDK pieces that we are using (for now):  pip install azure-mgmt-network

4.  Since this is now integrated into the CLI (v2.0.24 or later!):  pip install azure-cli-core
    Workflow!
    a.  Open command prompt, change to this directory, run dev_activate.bat, run "code ."
    b.  Write code!
    c.  When ready to test in cli, run install_extension.bat
        NOTE:  You may need to configure launch.json to run the CLI from the right place!
