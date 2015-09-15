## metastamp.py

Metastamp.py is a quick-and-dirty tool that recurses on a directory and extracts filesystem agnostic metadata from files it encounters. It displays them sorting records by date.

You can also specify a `--domains` parameter pointing to a domain list. Creation dates of the domains will be extracted (via whois) and added to the timeline.

Currently extracted timestamps:

* PE compile date
* RTF creation date
* PDF creation date
* Domain creation date (via whois)

## Requirements

```shell
> cat requirements.txt                                                                                                 3827
pefile==1.2.10.post114
python-whois==0.5.2
```

You can install those by running `pip install -r requirements.txt`

`exiftool` cannot be installed via `pip`, and must be installed "manually". Installation is still pretty straightforward: https://github.com/smarnach/pyexiftool


## Usage

Usage is pretty straightforward. Just point the tool to any directory:

    $ ./metastamp.py .

If you have a text file with domains you'd like to map to the timeline, specify it with `--domains FILE`.

    $ cat domains.txt
    tomchop.me
    google.com

    $ ls ~/Downloads
    152 -rw-r-----@ 1 tomchop  staff  73002 Sep 14 14:56 tmp1.exe
     16 -rw-r-----@ 1 tomchop  staff   6124 Sep 14 14:55 tmp4.exe
     16 -rw-r-----@ 1 tomchop  staff   6124 Sep 14 14:55 tmp5.exe

    $ ./metastamp.py --domains domains.txt ~/Downloads

    item                          	type                	timestamp
    ==============================	====================	====================
    google.com                    	Domain creation     	1997-09-15 00:00:00
    tmp1.exe                      	Compile timestamp   	2009-03-31 09:29:58
    tmp4.exe                      	Compile timestamp   	2010-04-14 22:06:53
    tmp5.exe                      	Compile timestamp   	2010-04-14 22:06:53
    tomchop.me                    	Domain creation     	2011-05-26 13:35:32
