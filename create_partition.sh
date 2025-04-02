#!/bin/bash
# Script na jednoduche vytvaranie/mazanie/mountovanie testovacich particii

# -----------------------------------------------
# Konstanty pre vytvaranie particii
# -----------------------------------------------
IMAGE_PATH="disk.img"
MOUNT_POINT="mnt"
IMAGE_SIZE="100M"  # Velkost disk image

# -----------------------------------------------
# Pomocne funkcie
# -----------------------------------------------

# Kontrola ci je skript spustany s pravami administratora
check_root() {
  if [ "$EUID" -ne 0 ]; then
    echo "Tento skript vyzaduje prava administratora (root)"
    echo "Spustite ho znova s prikazom: sudo $0 $*"
    exit 1
  fi
}

# Funkcia na vypisovanie spravy
print_status() {
  echo -e "\n[*] $1"
}

# Vytvorenie obrazu disku a particie
create_partition() {
  check_root
  print_status "Vytvorenie obrazu disku s velkostou $IMAGE_SIZE..."
  
  # Vytvorenie obrazu disku
  fallocate -l $IMAGE_SIZE $IMAGE_PATH
  
  # Vytvorenie partition table
  print_status "Vytvorenie partition table..."
  parted $IMAGE_PATH --script mklabel msdos
  
  # Vytvorenie primárnej particie
  print_status "Vytvorenie primarnej particie..."
  parted $IMAGE_PATH --script mkpart primary ext4 1MiB 100%
  
  # Pripojenie obrazku ako loopback zariadenie
  print_status "Pripajanie obrazku ako loopback zariadenie..."
  LOOP_DEVICE=$(losetup -f --show -P $IMAGE_PATH)
  
  # Formatovanie particie na ext4
  print_status "Formatovanie particie na ext4..."
  mkfs.ext4 ${LOOP_DEVICE}p1
  
  print_status "Particia uspesne vytvorena."
  print_status "Loop zariadenie: $LOOP_DEVICE"
  print_status "Particia: ${LOOP_DEVICE}p1"
}

# Pripojenie (mount) particie
mount_partition() {
  check_root
  # Vytvorenie adresara pre mount, ak este neexistuje
  if [ ! -d "$MOUNT_POINT" ]; then
    mkdir -p $MOUNT_POINT
  fi
  
  # Zistenie loop zariadenia
  LOOP_DEVICE=$(losetup -j $IMAGE_PATH | cut -d ":" -f 1)
  
  if [ -z "$LOOP_DEVICE" ]; then
    print_status "Pripajanie obrazku ako loopback zariadenie..."
    LOOP_DEVICE=$(losetup -f --show -P $IMAGE_PATH)
  fi
  
  print_status "Pripajanie particie ${LOOP_DEVICE}p1 na $MOUNT_POINT..."
  mount ${LOOP_DEVICE}p1 $MOUNT_POINT
  
  print_status "Particia uspesne pripojená."
  print_status "Particia: ${LOOP_DEVICE}p1"
  print_status "Pripojené v: $MOUNT_POINT"
}

# Odpojenie (unmount) particie
unmount_partition() {
  check_root
  LOOP_DEVICE=$(losetup -j $IMAGE_PATH | cut -d ":" -f 1)
  
  if [ -z "$LOOP_DEVICE" ]; then
    print_status "Particia nie je pripojena ako loopback zariadenie."
    return
  fi
  
  print_status "Odpajanie particii z $MOUNT_POINT..."
  umount $MOUNT_POINT 2>/dev/null || true
  
  print_status "Particia uspesne odpojená."
  print_status "Loopback zariadenie $LOOP_DEVICE zostava pripojene."
}

# Odpojenie loopback zariadenia
detach_loop() {
  check_root
  LOOP_DEVICE=$(losetup -j $IMAGE_PATH | cut -d ":" -f 1)
  
  if [ -z "$LOOP_DEVICE" ]; then
    print_status "Ziadne loopback zariadenie nie je priradene k obrazu $IMAGE_PATH."
    return
  fi
  
  # Skontrolujeme, ci je particia pripojená a ak áno, odpojíme ju
  if mount | grep -q "${LOOP_DEVICE}p1"; then
    print_status "Najprv odpajam particiu z $MOUNT_POINT..."
    umount $MOUNT_POINT 2>/dev/null || true
  fi
  
  print_status "Odpajanie loopback zariadenia..."
  losetup -d $LOOP_DEVICE 2>/dev/null || true
  
  print_status "Loopback zariadenie uspesne odpojené."
}

# Vyčistenie - odpojenie a zmazanie disk image
clean() {
  check_root
  unmount_partition
  detach_loop
  
  if [ -f "$IMAGE_PATH" ]; then
    print_status "Odstranovanie disk image $IMAGE_PATH..."
    rm -f $IMAGE_PATH
  fi
  
  print_status "Vsetko uspesne odstranené."
}

# Vytvorenie testovacieho suboru v particii
create_test_file() {
  check_root
  print_status "Vytvaranie testovacieho suboru v particii..."
  
  if [ ! -d "$MOUNT_POINT" ]; then
    print_status "Particia nie je pripojena. Najprv ju pripojte prikazom 'mount'."
    return
  fi
  
  echo "Toto je testovaci obsah pre particiu" > $MOUNT_POINT/test_file.txt
  echo "Testovaci subor vytvoreny: $MOUNT_POINT/test_file.txt"
}

# Vypisanie pomocnika
show_help() {
  echo "AES-XTS Tester particii"
  echo "Pouzitie: $0 [prikaz]"
  echo ""
  echo "Dostupné prikazy:"
  echo "  create   - Vytvori novu particiu v obraze disku"
  echo "  mount    - Pripoji particiu"
  echo "  unmount  - Odpoji particiu (ponecha loopback zariadenie)"
  echo "  detach   - Odpoji loopback zariadenie"
  echo "  clean    - Odpoji a vymaze vsetko"
  echo "  test     - Vytvori testovaci subor v particii"
  echo ""
  echo "Priklad pouzitia:"
  echo "  sudo $0 create     # Vytvori novu particiu"
  echo "  sudo $0 mount      # Pripoji particiu"
  echo "  sudo $0 unmount    # Odpoji particiu"
  echo "  sudo $0 detach     # Odpoji loopback zariadenie"
  echo "  sudo $0 clean      # Odstrani vsetko"
}

# -----------------------------------------------
# Hlavny program
# -----------------------------------------------
case "$1" in
  create)
    create_partition
    ;;
  mount)
    mount_partition
    ;;
  unmount)
    unmount_partition
    ;;
  detach)
    detach_loop
    ;;
  clean)
    clean
    ;;
  test)
    create_test_file
    ;;
  *)
    show_help
    ;;
esac

exit 0