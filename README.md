# Frida Installation and Usage Guide on Arch Linux with Genymotion

![Frida Logo](https://frida.re/images/frida-logo.png)

**Frida** is a dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers. It allows you to inject custom scripts into black-box processes, enabling powerful runtime manipulation and analysis of applications.

This guide provides a comprehensive step-by-step manual for installing and using Frida on **Arch Linux** with the **Genymotion** Android emulator. It includes installation scripts, configuration steps, and practical examples to help you get started with Frida.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [System Update and Dependency Installation](#system-update-and-dependency-installation)
3. [Installing Frida](#installing-frida)
4. [Setting Up Genymotion](#setting-up-genymotion)
5. [Installing Frida Server on Genymotion](#installing-frida-server-on-genymotion)
6. [Running Frida Server](#running-frida-server)
7. [Using Frida: Basic Commands and Examples](#using-frida-basic-commands-and-examples)
8. [Example Frida Scripts](#example-frida-scripts)
9. [Troubleshooting](#troubleshooting)
10. [Additional Resources](#additional-resources)
11. [License](#license)

---

## Prerequisites

Before you begin, ensure that you have the following:

- **Arch Linux** installed and running.
- **Genymotion** Android emulator installed.
- Basic knowledge of Linux command-line operations.
- **Root** access to your system and the Genymotion emulator (Genymotion devices are typically rooted by default).

---

## System Update and Dependency Installation

First, update your system and install the necessary dependencies.

### 1. Update Your System

Open your terminal and run:

```bash
sudo pacman -Syu
```

### 2. Install Required Packages

Install essential packages including `adb`, `wget`, `jq`, and `git`:

```bash
sudo pacman -S --needed adb wget jq git base-devel
```

### 3. Install `yay` (AUR Helper)

If you don't have an AUR helper like `yay` installed, follow these steps to install it:

```bash
# Clone the yay repository
git clone https://aur.archlinux.org/yay.git

# Navigate to the yay directory
cd yay

# Build and install yay
makepkg -si

# Navigate back to the home directory
cd ..
```

---

## Installing Frida

Frida can be installed using Python's `pip`. It's recommended to use a Python virtual environment to avoid conflicts with system packages.

### 1. Install Python and `pip`

Ensure Python and `pip` are installed:

```bash
sudo pacman -S python python-pip
```

### 2. Install Frida Tools

Install Frida using `pip`:

```bash
pip install --user frida-tools
```

### 3. Update Your `PATH`

Ensure that the local bin directory is in your `PATH`. Add the following line to your shell configuration file (`~/.bashrc` or `~/.zshrc`):

```bash
export PATH=$PATH:~/.local/bin
```

Apply the changes:

```bash
source ~/.bashrc  # or source ~/.zshrc
```

### 4. Verify Installation

Check the installed Frida version:

```bash
frida --version
```

You should see an output similar to:

```
16.2.20
```

---

## Setting Up Genymotion

Ensure that **Genymotion** is installed and configured on your system.

### 1. Install Genymotion

Download Genymotion from the [official website](https://www.genymotion.com/) and follow the installation instructions for Linux.

### 2. Launch Genymotion and Create a Virtual Device

1. Open Genymotion.
2. Log in with your Genymotion account.
3. Click on **Add** to create a new virtual device.
4. Choose an Android device template and download it.
5. Launch the virtual device.

### 3. Verify ADB Connection

Ensure that `adb` recognizes your Genymotion device:

```bash
adb devices
```

You should see output similar to:

```
List of devices attached
192.168.56.101:5555	device
```

---

## Installing Frida Server on Genymotion

To use Frida for debugging applications on your Genymotion emulator, you need to install **Frida Server** on the emulator. Below is a bash script that automates this process.

### 1. Create the Installation Script

Create a new file named `install_frida_genymotion.sh`:

```bash
nano install_frida_genymotion.sh
```

### 2. Add the Following Script to the File

```bash
#!/bin/bash

# Script to install Frida Server on Genymotion emulator

# Function to display informational messages
echo_info() {
    echo -e "\e[32m[INFO]\e[0m $1"
}

# Function to display error messages
echo_error() {
    echo -e "\e[31m[ERROR]\e[0m $1" >&2
}

# Check for required commands
for cmd in adb wget jq frida; do
    if ! command -v $cmd &> /dev/null; then
        echo_error "$cmd is not installed. Please install it and rerun the script."
        exit 1
    fi
done

# Check for connected devices
DEVICE_COUNT=$(adb devices | grep -w "device" | wc -l)
if [ "$DEVICE_COUNT" -eq 0 ]; then
    echo_error "No connected devices found. Please start your Genymotion emulator."
    exit 1
fi

# Get the first connected device ID
DEVICE_ID=$(adb devices | grep -w "device" | awk 'NR==1{print $1}')
echo_info "Connected device: $DEVICE_ID"

# Get device architecture
ARCH=$(adb -s "$DEVICE_ID" shell getprop ro.product.cpu.abi | tr -d '\r')
echo_info "Device architecture: $ARCH"

# Function to map device ABI to Frida ABI
get_frida_arch() {
    case "$1" in
        armv7l|armeabi-v7a)
            echo "arm"
            ;;
        aarch64|arm64-v8a)
            echo "arm64"
            ;;
        x86)
            echo "x86"
            ;;
        x86_64)
            echo "x86_64"
            ;;
        *)
            echo_error "Unknown architecture: $1"
            exit 1
            ;;
    esac
}

FRIDA_ARCH=$(get_frida_arch "$ARCH")
echo_info "Frida will be installed for architecture: $FRIDA_ARCH"

# Get Frida version
FRIDA_VERSION_RAW=$(frida --version)
if [ $? -ne 0 ] || [ -z "$FRIDA_VERSION_RAW" ]; then
    echo_error "Failed to determine Frida version. Ensure Frida is installed correctly."
    exit 1
fi

FRIDA_VERSION=$(echo "$FRIDA_VERSION_RAW" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
if [ -z "$FRIDA_VERSION" ]; then
    echo_error "Invalid Frida version format: $FRIDA_VERSION_RAW"
    exit 1
fi

echo_info "Using Frida version: $FRIDA_VERSION"

# Construct download URL
FRIDA_SERVER_NAME="frida-server-${FRIDA_VERSION}-android-${FRIDA_ARCH}.xz"
FRIDA_DOWNLOAD_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${FRIDA_SERVER_NAME}"

echo_info "Downloading Frida Server from: $FRIDA_DOWNLOAD_URL"

# Download Frida Server
wget -q --show-progress "$FRIDA_DOWNLOAD_URL" -O "/tmp/${FRIDA_SERVER_NAME}"
if [ $? -ne 0 ]; then
    echo_error "Failed to download Frida Server."
    exit 1
fi

echo_info "Frida Server downloaded to /tmp/${FRIDA_SERVER_NAME}"

# Extract Frida Server
echo_info "Extracting Frida Server..."
unxz "/tmp/${FRIDA_SERVER_NAME}"
FRIDA_SERVER_PATH="/tmp/frida-server-${FRIDA_VERSION}-android-${FRIDA_ARCH}"
if [ ! -f "$FRIDA_SERVER_PATH" ]; then
    echo_error "Failed to extract Frida Server."
    exit 1
fi

echo_info "Frida Server extracted to $FRIDA_SERVER_PATH"

# Push Frida Server to device
REMOTE_PATH="/data/local/tmp/frida-server"
echo_info "Pushing Frida Server to device at $REMOTE_PATH..."
adb -s "$DEVICE_ID" push "$FRIDA_SERVER_PATH" "$REMOTE_PATH"
if [ $? -ne 0 ]; then
    echo_error "Failed to push Frida Server to device."
    exit 1
fi

# Set execute permissions
echo_info "Setting execute permissions on Frida Server..."
adb -s "$DEVICE_ID" shell chmod 755 "$REMOTE_PATH"

# Start Frida Server
echo_info "Starting Frida Server on device..."
adb -s "$DEVICE_ID" shell "nohup $REMOTE_PATH >/dev/null 2>&1 &"

# Verify Frida Server is running
sleep 2
FRIDA_RUNNING=$(adb -s "$DEVICE_ID" shell ps | grep frida-server | wc -l)
if [ "$FRIDA_RUNNING" -ge 1 ]; then
    echo_info "Frida Server is running on the device."
    echo_info "Frida is ready to use!"
else
    echo_error "Failed to start Frida Server on the device."
    exit 1
fi

# Clean up temporary files
echo_info "Cleaning up temporary files..."
rm -f "/tmp/${FRIDA_SERVER_NAME}" "$FRIDA_SERVER_PATH"

echo_info "Frida Server installation completed successfully."
```

### 3. Save and Exit

Press `Ctrl + O` to save and `Ctrl + X` to exit the editor.

### 4. Make the Script Executable

```bash
chmod +x install_frida_genymotion.sh
```

### 5. Run the Installation Script

Ensure your Genymotion emulator is running, then execute the script:

```bash
./install_frida_genymotion.sh
```

**Script Workflow:**

1. **Checks for Required Tools:** Ensures that `adb`, `wget`, `jq`, and `frida` are installed.
2. **Detects Connected Device:** Identifies the first connected Genymotion device.
3. **Determines Device Architecture:** Uses `adb` to fetch the device's CPU architecture.
4. **Maps Architecture for Frida:** Converts the device's ABI to Frida-compatible architecture names.
5. **Fetches Frida Version:** Retrieves the installed Frida version on your host machine.
6. **Downloads Frida Server:** Downloads the appropriate Frida Server binary from GitHub.
7. **Transfers to Device:** Pushes the Frida Server binary to the Genymotion emulator.
8. **Sets Permissions and Runs:** Grants execute permissions and starts Frida Server on the emulator.
9. **Verifies Installation:** Confirms that Frida Server is running on the device.
10. **Cleans Up:** Removes temporary files used during installation.

---

## Running Frida Server

After installing Frida Server on your Genymotion emulator, you can interact with it using Frida tools on your host machine.

### 1. Verify Frida Server is Running

Run the following command to list processes on the device:

```bash
frida-ps -U
```

- `-U`: Connects to a USB device or network-connected device (Genymotion typically uses a network interface).

**Expected Output:**

```
 PID  Name
----  ---------------------
 1234  com.example.yourapp
 5678  com.android.systemui
 ...
```

If you see a list of processes, Frida is successfully connected to your Genymotion emulator.

---

## Using Frida: Basic Commands and Examples

Frida provides a suite of tools for dynamic instrumentation. Below are some basic commands and usage examples.

### 1. Listing Processes

List all processes running on the connected device:

```bash
frida-ps -U
```

List system and user processes:

```bash
frida-ps -Uai
```

### 2. Attaching to a Process

Attach to a running process by its name:

```bash
frida -U -n com.example.yourapp
```

Attach by process ID:

```bash
frida -U -p 1234
```

### 3. Injecting Scripts

Inject a custom script into a process to modify its behavior.

#### Example Script: `hook_oncreate.js`

```javascript
Java.perform(function () {
    var MainActivity = Java.use("com.example.yourapp.MainActivity");
    
    MainActivity.onCreate.overload("android.os.Bundle").implementation = function (savedInstanceState) {
        console.log("[+] onCreate called");
        this.onCreate(savedInstanceState);
    };
});
```

#### Injecting the Script

```bash
frida -U -n com.example.yourapp -l hook_oncreate.js --no-pause
```

- `-n`: Specifies the process name.
- `-l`: Loads the specified script.
- `--no-pause`: Starts the process immediately without pausing.

**Note:** If you encounter the error `unrecognized arguments: --no-pause`, ensure you are using the latest version of Frida. Alternatively, omit the flag and manually resume the process.

### 4. Interactive Console

Start an interactive Frida session:

```bash
frida -U -n com.example.yourapp
```

Within the console, you can execute JavaScript commands to interact with the process.

### 5. Using Frida CLI Tools

#### Frida-trace

Automatically hooks functions in a process.

**Example:** Trace `open` and `read` functions in a process:

```bash
frida-trace -U -i "open*" -i "read*" -n com.example.yourapp
```

#### Frida-ls-devices

List all connected devices recognized by Frida:

```bash
frida-ls-devices
```

---

## Example Frida Scripts

Below are some example Frida scripts to demonstrate common use cases.

### 1. Hooking a Java Method

**Script:** `hook_methods.js`

```javascript
Java.perform(function () {
    // Hooking a method in a Java class
    var Calculator = Java.use("com.example.yourapp.Calculator");
    
    // Overriding the 'add' method
    Calculator.add.overload('int', 'int').implementation = function (a, b) {
        console.log("[*] Calculator.add called with arguments: " + a + ", " + b);
        var result = this.add(a, b);
        console.log("[*] Result: " + result);
        return result;
    };
});
```

**Usage:**

```bash
frida -U -n com.example.yourapp -l hook_methods.js --no-pause
```

### 2. Enumerating Loaded Modules

**Script:** `enumerate_modules.js`

```javascript
Java.perform(function () {
    var modules = Process.enumerateModules();
    modules.forEach(function(module) {
        console.log("Module: " + module.name + ", Base Address: " + module.base);
    });
});
```

**Usage:**

```bash
frida -U -n com.example.yourapp -l enumerate_modules.js --no-pause
```

### 3. Monitoring Network Requests

**Script:** `monitor_network.js`

```javascript
Interceptor.attach(Module.findExportByName("libc.so", "connect"), {
    onEnter: function (args) {
        this.sock = args[0];
        this.addr = args[1];
        this.addrlen = args[2].toInt32();
    },
    onLeave: function (retval) {
        console.log("[*] connect called. Socket: " + this.sock);
    }
});
```

**Usage:**

```bash
frida -U -n com.example.yourapp -l monitor_network.js --no-pause
```

---

## Troubleshooting

### 1. Frida Server Not Running

- **Issue:** Frida commands return no devices or processes.
- **Solution:**
  - Ensure Frida Server is running on the device:
    ```bash
    adb shell ps | grep frida-server
    ```
  - Restart Frida Server:
    ```bash
    adb shell "pkill frida-server; nohup /data/local/tmp/frida-server >/dev/null 2>&1 &"
    ```
  - Verify network connectivity between host and emulator.

### 2. Version Mismatch

- **Issue:** Errors related to mismatched Frida versions.
- **Solution:**
  - Ensure that the Frida version on the host matches the Frida Server version on the device.
  - Reinstall Frida Server using the latest Frida version:
    ```bash
    ./install_frida_genymotion.sh
    ```

### 3. Permission Denied

- **Issue:** Unable to push Frida Server to the device.
- **Solution:**
  - Ensure the emulator is rooted.
  - Use `su` to gain superuser privileges when pushing files:
    ```bash
    adb root
    adb push frida-server /data/local/tmp/
    ```

### 4. `--no-pause` Argument Error

- **Issue:** Frida CLI reports `unrecognized arguments: --no-pause`.
- **Solution:**
  - Update Frida to the latest version:
    ```bash
    pip install --upgrade frida-tools
    ```
  - Alternatively, omit the `--no-pause` flag and manually resume:
    ```bash
    frida -U -f com.example.yourapp -l script.js
    # In the interactive session, type:
    resume()
    ```

---

## Additional Resources

- **Frida Official Documentation:** [https://frida.re/docs/home/](https://frida.re/docs/home/)
- **Frida GitHub Repository:** [https://github.com/frida/frida](https://github.com/frida/frida)
- **Genymotion Documentation:** [https://docs.genymotion.com/](https://docs.genymotion.com/)
- **Frida Examples:** [https://github.com/frida/frida/tree/master/examples](https://github.com/frida/frida/tree/master/examples)

---

