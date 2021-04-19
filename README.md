# lunatik
Lua in Kernel

Installation
------------

In order to compile Lunatik, first you have to meet the dependencies. To do that simply run the command:
```bash
git submodule update --recursive --init
```

After that, compile the code with
```bash
make -C /lib/modules/`uname -r`/build M=$PWD modules CONFIG_LUNATIK=m
```

with the code compiled you can now install the compiled module with
```bash
insmod lunatik.ko
```