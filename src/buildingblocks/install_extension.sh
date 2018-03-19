# @ECHO OFF

if [ -z "$AZURE_EXTENSION_DIR" ]
then
      echo "AZURE_EXTENSION_DIR not set";
      exit 1;
fi

pip install --upgrade --target "$AZURE_EXTENSION_DIR/azure-cli-block" .


