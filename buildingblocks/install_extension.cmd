@ECHO OFF

IF "%AZURE_EXTENSION_DIR%" == "" (
  ECHO AZURE_EXTENSION_DIR not set
  EXIT /B 1
)

pip install --upgrade --target %USERPROFILE%\.azure\devcliextensions\azure-cli-block %~dp0
