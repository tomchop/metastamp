## metastam.py

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
