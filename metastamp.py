#!/usr/bin/env python

import sys
import os
import time
import md5
import argparse

try:
    import pefile
    HAS_PEFILE = True
except ImportError as e:
    sys.stderr.write("Could not import 'pefile'. PE metadata won't be available")
    sys.stderr.write("Install: 'pip install pefile'")
    HAS_PEFILE = False

try:
    import whois
    HAS_WHOIS = True
except ImportError as e:
    sys.stderr.write("Could not import 'whois'. Domains creation dates won't be available.")
    sys.stderr.write("Install: 'pip install python-whois'")
    HAS_WHOIS = False

try:
    import exiftool
    HAS_EXIFTOOL = True
except ImportError as e:
    sys.stderr.write("Could not import 'exiftool'. PDF and RTF creation date won't be available.")
    sys.stderr.write("Installation instructions: https://github.com/smarnach/pyexiftool")
    HAS_EXIFTOOL = False


def is_pe(filename):
    with open(filename, 'rb') as hndl:
        if hndl.read(2) == "MZ":
            return True
    return False

def get_md5(filename):
    with open(filename, 'rb') as hndl:
        m = md5.new()
        while True:
            data = hndl.read(128)
            if not data:
                break
            m.update(data)
        return m.hexdigest()

def extract_timestamps_from_pe(fullpath, fname):
    entry = {}

    pe = pefile.PE(fullpath, fast_load=True)
    entry['epoch'] = time.gmtime(pe.FILE_HEADER.TimeDateStamp)
    entry['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S', entry['epoch'])
    entry['md5'] = get_md5(fullpath)
    entry['label'] = "{} compile timestamp".format(fname)
    entry['item'] = fname
    entry['type'] = 'Compile timestamp'

    return [entry]

def extract_timestamps_from_domain(domain):
    if not domain:
        return []

    w = whois.whois(domain)

    if isinstance(w.creation_date, list):
        dtime = w.creation_date[0]
    else:
        dtime = w.creation_date

    entry = {}
    entry['epoch'] = time.gmtime(int(dtime.strftime("%s")))
    entry['timestamp'] = dtime.strftime('%Y-%m-%d %H:%M:%S')
    entry['label'] = "{} creation date".format(domain)
    entry['item'] = domain
    entry['type'] = 'Domain creation'

    return [entry]


def extract_exif_timestamps(exif):

    entries = []

    with exiftool.ExifTool() as et:
        metadata = et.get_metadata_batch(exif)

    for d in metadata:
        entry = {}
        if 'File:MIMEType' in d:
            entry['item'] = d['File:FileName']

            if d['File:MIMEType'] == 'text/rtf':
                entry['epoch'] = time.strptime(d['RTF:CreateDate'], "%Y:%m:%d %H:%M:%S")

            if d['File:MIMEType'] == 'application/pdf':
                entry['epoch'] = time.strptime(d['PDF:CreateDate'][:19], "%Y:%m:%d %H:%M:%S")

            if 'epoch' in entry:
                entry['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S', entry['epoch'])
                entry['type'] = 'EXIF CreateDate'
                entries.append(entry)

    return entries

timeline = []

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Recurse in a directory extract various timestamps from files.')
    parser.add_argument('directory', type=str, help='The directory to recurse on')
    parser.add_argument('--domains', type=argparse.FileType('r'), help='Include the creation dates of these domains')

    args = parser.parse_args()

    exif = []

    for subdir, dirs, files in os.walk(args.directory):
        for fname in files:
            fullpath = os.path.join(subdir, fname)
            entry = None

            if is_pe(fullpath):
                entry = extract_timestamps_from_pe(fullpath, fname)

            if entry:
                timeline.extend(entry)

            if HAS_EXIFTOOL:
                exif.append(fullpath)

    if exif:
        timeline.extend(extract_exif_timestamps(exif))

    if args.domains and HAS_WHOIS:
        for domain in args.domains:
            if not domain.startswith('#'):
                entry = extract_timestamps_from_domain(domain.strip())
                timeline.extend(entry)

    timeline = sorted(timeline, key=lambda k: k['epoch'])
    sys.stdout.write("{: <30}\t{: <20}\t{}\n".format('item', 'type', 'timestamp'))
    sys.stdout.write("{:=<30}\t{:=<20}\t{:=<20}\n".format('', '', ''))
    for entry in timeline:
        sys.stdout.write("{: <30}\t{: <20}\t{:<20}\n".format(entry['item'][:28], entry['type'], entry['timestamp']))
