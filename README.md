# lunatik
Lua in Kernel

Dependencies
------------

Before proceeding to the installation of Lunatik, you have to install the following packages:
```bash
libnl-3-dev libnl-genl-3-dev liblua5.3-dev lua5.3
```

On Ubuntu this can be done with:
```bash
apt install libnl-3-dev libnl-genl-3-dev liblua5.3-dev lua5.3 -y
```

Installation
------------

In order to compile the Lunatik module, first you have to meet the dependencies. To do that simply run the command:
```bash
git submodule update --recursive --init
```

After that, compile the module with
```bash
make -C /lib/modules/`uname -r`/build M=$PWD modules CONFIG_LUNATIK=m
```

with the module compiled you can now install it with
```bash
insmod lunatik.ko
```

Now, let's install the userspace API to manage lua states. On the directory `lib` run `make`. To run the tests just run the command `./runtests.sh` inside the `lib` folder. Running that, you should see something like:

```bash
File tests/close.lua executed with no errors
File tests/create.lua executed with no errors
File tests/getstate.lua executed with no errors
File tests/list.lua executed with no errors
File tests/receive.lua executed with no errors
File tests/send.lua executed with no errors
File tests/session.lua executed with no errors
```

This means that the Lunatik was successfully installed.

Uninstall
---------

To remove lunatik module just run the command
```bash
rmmod lunatik
```