#!/system/bin/sh
# =============================================================================
# Bionic FakeLock Property Verification Script
# =============================================================================

echo "========================================="
echo "   Bionic FakeLock Verification Check"
echo "========================================="

check_prop() {
    NAME=$1
    EXPECTED=$2
    VAL=$(getprop "$NAME")
    if [ "$VAL" = "$EXPECTED" ]; then
        echo "[PASS] $NAME = '$VAL'"
    else
        echo "[WARN] $NAME = '$VAL' (Expected: '$EXPECTED')"
    fi
}

check_prop "ro.boot.flash.locked" "1"
check_prop "ro.boot.verifiedbootstate" "green"
check_prop "ro.boot.vbmeta.device_state" "locked"

echo "-----------------------------------------"
echo "System status:"
echo "sys.boot_completed = $(getprop sys.boot_completed)"
echo "ro.build.version.release = $(getprop ro.build.version.release)"
echo "========================================="
