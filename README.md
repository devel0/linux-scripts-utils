# linux-scripts-utils

linux bash script utils

## install

- clone repo

```
cd /
git clone https://github.com/devel0/linux-scripts-utils
mv linux-script-utils scripts
```

- add `/scripts` to path in `/etc/environment`

## nautilus scripts

this will add gnome actions by enabling a script menu to add contextual actions

```
cd linux-scripts-utils
mkdir -p ~/.local/share/nautilus/scripts
cp nautilus-scripts/* ~/.local/share/nautilus/scripts
chmod +x ~/.local/share/nautilus/scripts
```
