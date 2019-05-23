# icyque
ICQ WIM protocol for libpurple

# Installation #
## Linux install ##
Download latest builds from https://bamboo.pidgin.im/browse/EIONROBB-ICYQUE/latestSuccessful/artifact/shared/builds/ and copy into ~/.purple/plugins/ directory.

### Manual Compiling ###
Requires devel headers/libs for libpurple and libjson-glib [libglib2.0-dev, libjson-glib-dev and libpurple-dev]
```bash
	git clone git://github.com/EionRobb/icyque.git
	cd icyque
	make
	sudo make install
```

## Windows install ##
Download nightly builds of [libicyque.dll](https://eion.robbmob.com/libicyque.dll) and copy into your C:\Program Files (x86)\Pidgin\plugins\ folder
If you haven't used one of my other plugins before, you'll need [libjson-glib-1.0.dll](https://eion.robbmob.com/libjson-glib-1.0.dll) in your C:\Program Files (x86)\Pidgin\ (not plugins!) folder

# Setup #
If you're switching to IcyQue from the built-in ICQ plugin, you'll need to restart Pidgin and then edit your existing account (or create a new account) with the "ICQ (WIM)" protocol:

![image](https://user-images.githubusercontent.com/1063865/55356131-95b07b00-5526-11e9-9fb8-27e0fc18ce74.png)

If you only have a phone number, then enter that with a + at the beginning and leave the password field blank

![image](https://user-images.githubusercontent.com/1063865/58231424-15baca80-7d8b-11e9-9f85-e6d502ee3dfd.png)
