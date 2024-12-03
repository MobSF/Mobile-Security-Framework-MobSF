#!/bin/bash

# Check if START_PORT, AVD_NAME, and open_gapps.zip are provided as arguments
AVD_NAME=$1
START_PORT=${2:-5554}
GAPPS_ZIP=$3

# Determine the emulator path based on OS
if [ "$(uname)" = "Darwin" ]; then
  EMULATOR_PATH="$HOME/Library/Android/sdk/emulator/emulator"
elif [ "$(uname)" = "Linux" ]; then
  EMULATOR_PATH="$HOME/Android/Sdk/emulator/emulator"
else
  echo "$(tput setaf 1)Unsupported OS: $(uname)$(tput sgr0)"
  exit 1
fi

# Check if the emulator path exists and is executable
if [ ! -x "$EMULATOR_PATH" ]; then
  echo "$(tput setaf 1)Emulator not found at $EMULATOR_PATH$(tput sgr0)"
  exit 1
fi

# Locate adb path
if [ -x "$HOME/Android/Sdk/platform-tools/adb" ]; then
  ADB_PATH="$HOME/Android/Sdk/platform-tools/adb"
elif [ -x "$HOME/Library/Android/sdk/platform-tools/adb" ]; then
  ADB_PATH="$HOME/Library/Android/sdk/platform-tools/adb"
elif command -v adb >/dev/null 2>&1; then
  ADB_PATH=$(command -v adb)
else
  echo "$(tput setaf 3)adb not found in common locations. Defaulting to 'adb' in PATH.$(tput sgr0)"
  ADB_PATH="adb"
fi

# Check if adb is available
if [ ! -x "$ADB_PATH" ]; then
  echo "$(tput setaf 1)adb not found at $ADB_PATH$(tput sgr0)"
  exit 1
fi

# If no AVD_NAME is provided, list available AVDs and exit
if [ -z "$AVD_NAME" ]; then
  echo -e "$(tput bold)Available AVDs:$(tput sgr0)\n"
  "$EMULATOR_PATH" -list-avds
  echo -e "$(tput bold)\nUse any Android AVD 5.0 - 11.0, up to API 30 without Google Play (production image).$(tput sgr0)"
  echo "$(tput bold)Usage: $0 AVD_NAME [START_PORT] [open_gapps.zip path]$(tput sgr0)"
  echo "$(tput bold)Example: $0 Pixel_6_Pro_API_28 5554 /path/to/open_gapps.zip$(tput sgr0)"
  exit 1
fi

# Check if provided AVD_NAME exists in available AVDs
AVAILABLE_AVDS=$("$EMULATOR_PATH" -list-avds)
if ! echo "$AVAILABLE_AVDS" | grep -q "^$AVD_NAME$"; then
  echo "$(tput setaf 1)Error: AVD $AVD_NAME not found in available AVDs.$(tput sgr0)"
  echo "$(tput bold)Available AVDs:$(tput sgr0)"
  echo "$AVAILABLE_AVDS"
  exit 1
fi

# Kill any existing emulator processes
for pid in $(pgrep -f emulator); do
  echo "Killing emulator process with PID $pid"
  kill -9 "$pid"
done

# Start the emulator with user-defined AVD and port
"$EMULATOR_PATH" -avd "$AVD_NAME" -writable-system -no-snapshot -wipe-data -port "$START_PORT" >/dev/null 2>&1 &
echo "$(tput setaf 2)Starting AVD $AVD_NAME on port $START_PORT$(tput sgr0)"
echo "Waiting for emulator to boot..."
"$ADB_PATH" wait-for-device

# Check if socat is available only on Linux
if [ "$(uname)" = "Linux" ]; then
  if command -v socat >/dev/null; then
    SOCAT_AVAILABLE=true
  else
    SOCAT_AVAILABLE=false
    echo "$(tput setaf 3)Warning: socat is not installed. Skipping port forwarding with socat. This might be required for docker in Linux.$(tput sgr0)"
  fi
else
  SOCAT_AVAILABLE=false
fi

# Increment ports and start socat listeners if socat is available
if [ "$SOCAT_AVAILABLE" = true ]; then
  LISTEN_PORT=$((START_PORT + 2))
  TARGET_PORT=$((START_PORT + 1))
  # Remove all previous forwards
  for pid in $(lsof -t -i TCP:$LISTEN_PORT -sTCP:LISTEN -c socat); do
    echo "Killing socat process on port $LISTEN_PORT with PID $pid"
    kill -9 "$pid"
  done
  # Start a single socat listener
  socat TCP-LISTEN:$LISTEN_PORT,fork,reuseaddr TCP:localhost:$TARGET_PORT &
  
  echo "socat listener started on port $LISTEN_PORT forwarding to $TARGET_PORT in the host."
  echo "$(tput bold)Docker users please set the environment variable MOBSF_ANALYZER_IDENTIFIER=host.docker.internal:$LISTEN_PORT for adb connectivity.$(tput sgr0)"
fi

# Install Play Store if open_gapps.zip is provided
if [ -n "$GAPPS_ZIP" ]; then
  if [ ! -f "$GAPPS_ZIP" ]; then
    echo "$(tput setaf 1)Error: File $GAPPS_ZIP not found.$(tput sgr0)"
    exit 1
  fi

  echo "Installing PlayStore"

  if ! command -v unzip >/dev/null; then
    echo "$(tput setaf 1)Error: unzip is not installed.$(tput sgr0)"
    exit 1
  fi

  if ! command -v lzip >/dev/null; then
    echo "$(tput setaf 1)Error: lzip is not installed.$(tput sgr0)"
    exit 1
  fi
  
  PLAY_EXTRACT_DIR="play"
  [ -d "$PLAY_EXTRACT_DIR" ] && rm -rf $PLAY_EXTRACT_DIR
  unzip "$GAPPS_ZIP" 'Core/*' -d ./$PLAY_EXTRACT_DIR || { echo "$(tput setaf 1)Error: Unzip failed$(tput sgr0)"; exit 1; }
  rm $PLAY_EXTRACT_DIR/Core/setup*
  lzip -d $PLAY_EXTRACT_DIR/Core/*.lz || { echo "$(tput setaf 1)Error: Decompression failed$(tput sgr0)"; exit 1; }
  for f in $(ls $PLAY_EXTRACT_DIR/Core/*.tar); do
    tar -x --strip-components 2 -f $f -C $PLAY_EXTRACT_DIR || { echo "$(tput setaf 1)Error: Extraction failed$(tput sgr0)"; exit 1; }
  done

  echo "Waiting for the emulator to be ready..."
  sleep 25
  echo "Installing PlayStore components"
  "$ADB_PATH" root
  "$ADB_PATH" remount >/dev/null 2>&1
  "$ADB_PATH" push $PLAY_EXTRACT_DIR/etc /system
  "$ADB_PATH" push $PLAY_EXTRACT_DIR/framework /system
  "$ADB_PATH" push $PLAY_EXTRACT_DIR/app /system
  "$ADB_PATH" push $PLAY_EXTRACT_DIR/priv-app /system
  "$ADB_PATH" shell stop
  "$ADB_PATH" shell start
  [ -d "$PLAY_EXTRACT_DIR" ] && rm -rf $PLAY_EXTRACT_DIR
  echo "PlayStore installed successfully"
else
  echo "$(tput setaf 3)No open_gapps.zip provided. Skipping Play Store installation.$(tput sgr0)"
fi
