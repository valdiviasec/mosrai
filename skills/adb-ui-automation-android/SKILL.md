---
name: adb-ui-automation-android
description: Use when you need to programmatically interact with an Android app via ADB without manual input: entering values, tapping buttons, and reading UI results. Triggers - "adb automation", "uiautomator", "programmatic input", "adb tap validate"
platform: [android]
stack: [native]
category: recon
tier: B
related: []
---

# Skill: ADB UI Automation for Android App Testing

## When to use
Driving an Android app's UI via ADB without manual interaction. Useful when
you need to input a value, tap a validate button, and check the result
programmatically.

## Core commands

### Install and launch
```bash
adb install -r app.apk
adb shell am start -n <package>/.<MainActivity>
```

### Dump UI hierarchy (find elements + coordinates)
```bash
adb shell uiautomator dump /sdcard/ui.xml
adb pull /sdcard/ui.xml
# Parse for resource-id, text, bounds
grep -oE 'resource-id="[^"]*"|text="[^"]*"|bounds="[^"]*"' ui.xml
```

### Input text
```bash
adb shell input tap <x> <y>          # focus the field first
adb shell input text "your-input"
```

**IMPORTANT:** `adb input text` does NOT support spaces. Replace with `%s`.
Also avoid special chars like `&`, `<`, `>`: URL-encode if needed.

### Tap a button (compute center from bounds)
```bash
# bounds="[424,1640][655,1766]" -> center = (539, 1703)
center_x = (left + right) // 2
center_y = (top + bottom) // 2
adb shell input tap <center_x> <center_y>
```

### Key events
```bash
adb shell input keyevent KEYCODE_BACK    # dismiss dialog / hide keyboard
adb shell input keyevent KEYCODE_DEL     # delete char
adb shell input keyevent KEYCODE_MOVE_END  # cursor to end
adb shell input keyevent KEYCODE_HOME     # cursor to start
```

## Critical gotcha: phantom keystrokes

**Problem:** When the soft keyboard is visible and you tap a button, the tap may
register an extra keystroke (especially on Genymotion/emulators). This corrupts
the input field.

**Solution:** Always hide the keyboard before tapping the validate button:
```bash
adb shell input text "your-input"
adb shell input keyevent KEYCODE_BACK    # hide keyboard FIRST
# Now find the button's new bounds (they shift when keyboard hides)
adb shell uiautomator dump /sdcard/ui.xml
adb pull /sdcard/ui.xml
# Recompute button center, then tap
adb shell input tap <new_x> <new_y>
```

## Clearing a field
```bash
adb shell input keyevent KEYCODE_MOVE_END
for i in $(seq 1 50); do
    adb shell input keyevent KEYCODE_DEL >/dev/null 2>&1
done
```

## Checking validation result

### Method 1: UI dump
```bash
adb shell uiautomator dump /sdcard/result.xml
adb pull /sdcard/result.xml
grep -oE 'text="[^"]*"' result.xml | grep -i "congrat\|wrong\|success\|fail"
```

### Method 2: logcat (if app logs)
```bash
adb logcat -c                              # clear before
adb shell input tap <validate_x> <y>       # trigger
sleep 2
adb logcat -d | grep -iE "congrat|flag|token|VAL|wrong|missing"
```

### Method 3: Screenshot
```bash
adb shell screencap -p /sdcard/screen.png
adb pull /sdcard/screen.png
```

## Full automation script (bash)

```bash
#!/bin/bash
PKG="com.example.app"
FIELD_BOUNDS="[21,1399][1059,1517]"   # from uiautomator dump
BTN_TEXT="VALIDATE"
INPUT="test-input-123"

adb logcat -c
adb shell am start -n $PKG/.MainActivity
sleep 2
adb shell input keyevent KEYCODE_BACK    # dismiss "older Android" warning

# Focus field and type
FIELD_CENTER=$(( (21+1059)/2 )),$(( (1399+1517)/2 ))
adb shell input tap ${FIELD_CENTER%,*} ${FIELD_CENTER#*,}
sleep 1
adb shell input text "$INPUT"
adb shell input keyevent KEYCODE_BACK    # hide keyboard

# Find and tap VALIDATE
adb shell uiautomator dump /sdcard/ui.xml
adb pull /sdcard/ui.xml
BTN_BOUNDS=$(grep "$BTN_TEXT" ui.xml | grep -oE 'bounds="\[[0-9,]+\]\[[0-9,]+\]"')
# parse and compute center (use python or awk for precision)
```

## Dismissing system dialogs
Newer Android shows "This app was built for an older version" dialog on old apps:
```bash
adb shell input keyevent KEYCODE_BACK
# Or tap "OK" / "Dismiss" button:
adb shell uiautomator dump /sdcard/ui.xml
adb pull /sdcard/ui.xml
grep "button1\|OK\|Dismiss" ui.xml  # find and tap
```