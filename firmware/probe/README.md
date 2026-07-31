# The slot probe

A slot-linked program that reports where it is running from and lets the state record be driven
by hand. It exists so the boot chain — package, flash, jump, trial, revert — can be exercised
without the radio, which means it can be exercised on a plain Pico 2 or Pico as well as on the
boards that are sold.

That matters because everything specific to the RP2350 in this design is in the parts the probe
covers: how a relocated image is packaged, and how the loader hands over on a Cortex-M33 (`VTOR`,
`MSPLIM`, two banks of NVIC registers instead of one). None of it involves Wi-Fi, and the Pico 2
has the same 4 MB flash as the Pico 2 W, so the layout under test is identical.

## Build

```sh
export PICO_SDK_PATH=/path/to/pico-sdk

cmake -S ../loader -B ../../build-loader -G Ninja -DCMAKE_BUILD_TYPE=Release -DPICO_BOARD=pico2
cmake --build ../../build-loader

cmake -S . -B ../../build-probe-a -G Ninja -DCMAKE_BUILD_TYPE=Release -DPICO_BOARD=pico2 -DRW_SLOT=a
cmake --build ../../build-probe-a
cmake -S . -B ../../build-probe-b -G Ninja -DCMAKE_BUILD_TYPE=Release -DPICO_BOARD=pico2 -DRW_SLOT=b
cmake --build ../../build-probe-b
```

## Install

One file at a time, loader first, letting the board restart between each. With no bootable slot
the loader returns to the ROM bootloader by itself, so the drive comes back on its own and the
next file can be copied straight away.

```
loader.uf2      ->  0x10000000
probe-a.uf2     ->  0x10010000
probe-b.uf2     ->  0x100c0000
```

## Use

Open the serial port. The probe prints every three seconds, so nothing is missed by connecting
late:

```
probe slot-a  board=pico2_w  fw=1.5.0  flash=4096 KB
  running slot A   xip=10010000  main=100104f1  vtor=10010100
  record: seq=3 active=A fallback=A trial=0 confirmed=yes version=1.5.0
  keys: s state  c confirm  x stage the other slot  r reboot  b bootsel
```

`board=` is derived from the chip, so a plain Pico 2 reports itself as `pico2_w`; the two are
indistinguishable to the firmware and only the wireless one is sold.

| Key | Does |
|---|---|
| `s` | Print the state record now |
| `c` | Confirm the running image, ending its trial |
| `x` | Stage the other slot, on trial |
| `r` | Reboot through the watchdog |
| `b` | Reboot into the ROM bootloader |

### Proving a rollback

With both slots holding a probe, from slot A press `x` then `r`. Slot B comes up on trial with
three boots left. Press `r` twice more without confirming, and the fourth boot lands back in slot
A — the loader reverted, and the record says so.

The same sequence with `c` pressed while B is on trial ends with B confirmed and A kept as the
fallback, which is what a successful update looks like.
