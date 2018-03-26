import "hash"

rule r383d4d582ae31a5bcca5fbef4068c61c {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.60 64bit (2017-07-17 07:30:52)"
        author = "@viql"
        date = "2018-03-26"
        sample = "383d4d582ae31a5bcca5fbef4068c61c"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 462848 and
        hash.md5(0,filesize) ==  "383d4d582ae31a5bcca5fbef4068c61c"
}        
        
rule rec58af9975f6322fbe54ef8861c4ab25 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.71 64bit (2017-11-08 12:31:23)"
        author = "@viql"
        date = "2018-03-26"
        sample = "ec58af9975f6322fbe54ef8861c4ab25"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 466944 and
        hash.md5(0,filesize) ==  "ec58af9975f6322fbe54ef8861c4ab25"
}        
        
rule r2967e39fe0b22f020489028f159c620b {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.80 64bit (2018-01-09 20:01:21)"
        author = "@viql"
        date = "2018-03-26"
        sample = "2967e39fe0b22f020489028f159c620b"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 712704 and
        hash.md5(0,filesize) ==  "2967e39fe0b22f020489028f159c620b"
}        
        
rule re0b43753cf06c3ccd65c9e5b54fb74ee {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.80 32bit (2018-01-09 20:01:07)"
        author = "@viql"
        date = "2018-03-26"
        sample = "e0b43753cf06c3ccd65c9e5b54fb74ee"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 487424 and
        hash.md5(0,filesize) ==  "e0b43753cf06c3ccd65c9e5b54fb74ee"
}        
        
rule ra889fc46b4eed4a031343706ea731157 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.82 64bit (2018-02-15 15:18:43)"
        author = "@viql"
        date = "2018-03-26"
        sample = "a889fc46b4eed4a031343706ea731157"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 647168 and
        hash.md5(0,filesize) ==  "a889fc46b4eed4a031343706ea731157"
}        
        
rule r1677932806f6cad5af01fa3a58bed742 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.82 32bit (2018-02-05 08:48:30)"
        author = "@viql"
        date = "2018-03-26"
        sample = "1677932806f6cad5af01fa3a58bed742"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 487424 and
        hash.md5(0,filesize) ==  "1677932806f6cad5af01fa3a58bed742"
}        
        
rule r2ef3236e531301a52756d262c7a3249f {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.82 64bit (2018-02-14 09:17:49)"
        author = "@viql"
        date = "2018-03-26"
        sample = "2ef3236e531301a52756d262c7a3249f"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 651264 and
        hash.md5(0,filesize) ==  "2ef3236e531301a52756d262c7a3249f"
}        
        
rule r56152d48f52c337e2348c75254f142db {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.62 32bit (2017-08-20 16:03:41)"
        author = "@viql"
        date = "2018-03-26"
        sample = "56152d48f52c337e2348c75254f142db"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 331776 and
        hash.md5(0,filesize) ==  "56152d48f52c337e2348c75254f142db"
}        
        
rule r8319f4b39bd607041bc71e6b748fb533 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.65 64bit (2017-09-04 18:29:51)"
        author = "@viql"
        date = "2018-03-26"
        sample = "8319f4b39bd607041bc71e6b748fb533"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 471040 and
        hash.md5(0,filesize) ==  "8319f4b39bd607041bc71e6b748fb533"
}        
        
rule rbc303564876fb407642032cf93a93058 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.85 64bit (2018-03-11 07:22:01)"
        author = "@viql"
        date = "2018-03-26"
        sample = "bc303564876fb407642032cf93a93058"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "bc303564876fb407642032cf93a93058"
}        
        
rule r6d3b2c5ee970e7c37d24dce9d9f70666 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.85 64bit (2018-02-27 09:23:53)"
        author = "@viql"
        date = "2018-03-26"
        sample = "6d3b2c5ee970e7c37d24dce9d9f70666"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 696320 and
        hash.md5(0,filesize) ==  "6d3b2c5ee970e7c37d24dce9d9f70666"
}        
        
rule r81135fa4b14a33cdbda15ebc1ec58294 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.68 64bit (2017-10-30 07:04:49)"
        author = "@viql"
        date = "2018-03-26"
        sample = "81135fa4b14a33cdbda15ebc1ec58294"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 442368 and
        hash.md5(0,filesize) ==  "81135fa4b14a33cdbda15ebc1ec58294"
}        
        
rule rdf80d463f19b61f2bc10622e2172fd36 {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.85 64bit (2018-03-11 07:48:28)"
        author = "@viql"
        date = "2018-03-26"
        sample = "df80d463f19b61f2bc10622e2172fd36"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "df80d463f19b61f2bc10622e2172fd36"
}        
        
rule r1dcfab5e9a43ce0320bf05e2bed0e8f3 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.72 32bit (2017-11-16 10:49:17)"
        author = "@viql"
        date = "2018-03-26"
        sample = "1dcfab5e9a43ce0320bf05e2bed0e8f3"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 352256 and
        hash.md5(0,filesize) ==  "1dcfab5e9a43ce0320bf05e2bed0e8f3"
}        
        
rule r8d26bc42ba1906fefe4c4f63c4b0802e {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.85 64bit (2018-03-11 07:45:56)"
        author = "@viql"
        date = "2018-03-26"
        sample = "8d26bc42ba1906fefe4c4f63c4b0802e"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "8d26bc42ba1906fefe4c4f63c4b0802e"
}        
        
rule rd8c6f5d7d60a8c10fe1773c50d426079 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.66 64bit (2017-09-18 05:13:14)"
        author = "@viql"
        date = "2018-03-26"
        sample = "d8c6f5d7d60a8c10fe1773c50d426079"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 466944 and
        hash.md5(0,filesize) ==  "d8c6f5d7d60a8c10fe1773c50d426079"
}        
        
rule rb63214353184663530521e41f1452078 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.71 32bit (2017-11-08 12:31:10)"
        author = "@viql"
        date = "2018-03-26"
        sample = "b63214353184663530521e41f1452078"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 348160 and
        hash.md5(0,filesize) ==  "b63214353184663530521e41f1452078"
}        
        
rule rf41fb1019007c5e03ff3d38ee91523dd {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.85 64bit (2018-03-11 07:48:28)"
        author = "@viql"
        date = "2018-03-26"
        sample = "f41fb1019007c5e03ff3d38ee91523dd"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "f41fb1019007c5e03ff3d38ee91523dd"
}        
        
rule r303299aca690f1d5de966b542c89e10f {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.66 64bit (2017-09-10 16:17:45)"
        author = "@viql"
        date = "2018-03-26"
        sample = "303299aca690f1d5de966b542c89e10f"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 442368 and
        hash.md5(0,filesize) ==  "303299aca690f1d5de966b542c89e10f"
}        
        
rule ra0de22f3b01556deeae2c90a690b5845 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.68 64bit (2017-10-18 11:34:02)"
        author = "@viql"
        date = "2018-03-26"
        sample = "a0de22f3b01556deeae2c90a690b5845"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 446464 and
        hash.md5(0,filesize) ==  "a0de22f3b01556deeae2c90a690b5845"
}        
        
rule re755a16547585be1e7338762828c88f0 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.85 32bit (2018-03-20 09:33:41)"
        author = "@viql"
        date = "2018-03-26"
        sample = "e755a16547585be1e7338762828c88f0"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 487424 and
        hash.md5(0,filesize) ==  "e755a16547585be1e7338762828c88f0"
}        
        
rule r063ef17c48eae1c326e6cd97364e5f9f {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.80 32bit (2017-12-16 13:22:48)"
        author = "@viql"
        date = "2018-03-26"
        sample = "063ef17c48eae1c326e6cd97364e5f9f"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 352256 and
        hash.md5(0,filesize) ==  "063ef17c48eae1c326e6cd97364e5f9f"
}        
        
rule r3113f7ca01b174211eae1a3a8f1614df {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.85 32bit (2018-03-11 07:48:14)"
        author = "@viql"
        date = "2018-03-26"
        sample = "3113f7ca01b174211eae1a3a8f1614df"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "3113f7ca01b174211eae1a3a8f1614df"
}        
        
rule redba64cb2157ddb77cb33cc428a48076 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.77 32bit (2017-12-08 20:44:29)"
        author = "@viql"
        date = "2018-03-26"
        sample = "edba64cb2157ddb77cb33cc428a48076"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 352256 and
        hash.md5(0,filesize) ==  "edba64cb2157ddb77cb33cc428a48076"
}        
        
rule r32ac659d0f4233bc4bf98ada3f550406 {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.82 64bit (2018-02-05 09:24:10)"
        author = "@viql"
        date = "2018-03-26"
        sample = "32ac659d0f4233bc4bf98ada3f550406"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 753664 and
        hash.md5(0,filesize) ==  "32ac659d0f4233bc4bf98ada3f550406"
}        
        
rule ra40ba82daea1dce261b2231d2eb8fd70 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.80 32bit (2018-01-18 13:04:02)"
        author = "@viql"
        date = "2018-03-26"
        sample = "a40ba82daea1dce261b2231d2eb8fd70"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "a40ba82daea1dce261b2231d2eb8fd70"
}        
        
rule r0caaae681f61ba974bd5d4a013312ee2 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.67 64bit (2017-10-02 22:23:23)"
        author = "@viql"
        date = "2018-03-26"
        sample = "0caaae681f61ba974bd5d4a013312ee2"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 446464 and
        hash.md5(0,filesize) ==  "0caaae681f61ba974bd5d4a013312ee2"
}        
        
rule r365d8ce82f257d9489a6db7f6cf01517 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.60 64bit (2017-07-09 17:02:37)"
        author = "@viql"
        date = "2018-03-26"
        sample = "365d8ce82f257d9489a6db7f6cf01517"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 450560 and
        hash.md5(0,filesize) ==  "365d8ce82f257d9489a6db7f6cf01517"
}        
        
rule r2a02912728b77f6a5cc57812dac7be62 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.68 32bit (2017-10-18 11:33:35)"
        author = "@viql"
        date = "2018-03-26"
        sample = "2a02912728b77f6a5cc57812dac7be62"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 352256 and
        hash.md5(0,filesize) ==  "2a02912728b77f6a5cc57812dac7be62"
}        
        
rule r353053924fb970d00e3ad897eeaa1ff5 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.85 32bit (2018-02-19 06:53:37)"
        author = "@viql"
        date = "2018-03-26"
        sample = "353053924fb970d00e3ad897eeaa1ff5"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 491520 and
        hash.md5(0,filesize) ==  "353053924fb970d00e3ad897eeaa1ff5"
}        
        
rule r7c7d957fcd93ef3d1b78054aa2fb4472 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.83 32bit (2018-02-16 07:07:06)"
        author = "@viql"
        date = "2018-03-26"
        sample = "7c7d957fcd93ef3d1b78054aa2fb4472"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 491520 and
        hash.md5(0,filesize) ==  "7c7d957fcd93ef3d1b78054aa2fb4472"
}        
        
rule rd25709b54bb78ed8e34652bf23072dae {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.74 32bit (2017-11-21 13:51:49)"
        author = "@viql"
        date = "2018-03-26"
        sample = "d25709b54bb78ed8e34652bf23072dae"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 348160 and
        hash.md5(0,filesize) ==  "d25709b54bb78ed8e34652bf23072dae"
}        
        
rule rcc7e2f70a966f286723c8009ba55f853 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.60 32bit (2017-06-28 21:58:14)"
        author = "@viql"
        date = "2018-03-26"
        sample = "cc7e2f70a966f286723c8009ba55f853"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 339968 and
        hash.md5(0,filesize) ==  "cc7e2f70a966f286723c8009ba55f853"
}        
        
rule r94fd7c297e7ddc4dc2ba51af095685d0 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.82 32bit (2018-02-05 09:27:42)"
        author = "@viql"
        date = "2018-03-26"
        sample = "94fd7c297e7ddc4dc2ba51af095685d0"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "94fd7c297e7ddc4dc2ba51af095685d0"
}        
        
rule rbf91a9159929614de2f9dc95c59de516 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.67 32bit (2017-10-12 23:31:56)"
        author = "@viql"
        date = "2018-03-26"
        sample = "bf91a9159929614de2f9dc95c59de516"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 348160 and
        hash.md5(0,filesize) ==  "bf91a9159929614de2f9dc95c59de516"
}        
        
rule r876fa2bab0a90e8d84045f71bb84f734 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.85 32bit (2018-02-20 13:02:28)"
        author = "@viql"
        date = "2018-03-26"
        sample = "876fa2bab0a90e8d84045f71bb84f734"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 491520 and
        hash.md5(0,filesize) ==  "876fa2bab0a90e8d84045f71bb84f734"
}        
        
rule r8deb67a267969ce49f87cc3623849507 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.65 32bit (2017-09-04 18:28:42)"
        author = "@viql"
        date = "2018-03-26"
        sample = "8deb67a267969ce49f87cc3623849507"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 352256 and
        hash.md5(0,filesize) ==  "8deb67a267969ce49f87cc3623849507"
}        
        
rule rb23a9bd3ee31af8b78d18bb92e7f2257 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.85 64bit (2018-02-19 06:53:59)"
        author = "@viql"
        date = "2018-03-26"
        sample = "b23a9bd3ee31af8b78d18bb92e7f2257"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 675840 and
        hash.md5(0,filesize) ==  "b23a9bd3ee31af8b78d18bb92e7f2257"
}        
        
rule r3f7155b3a742fdf5d8539ec384090510 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.82 64bit (2018-02-05 08:48:40)"
        author = "@viql"
        date = "2018-03-26"
        sample = "3f7155b3a742fdf5d8539ec384090510"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 753664 and
        hash.md5(0,filesize) ==  "3f7155b3a742fdf5d8539ec384090510"
}        
        
rule r7ca54a11bf979832c19000d53874bb23 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.85 64bit (2018-02-20 13:02:42)"
        author = "@viql"
        date = "2018-03-26"
        sample = "7ca54a11bf979832c19000d53874bb23"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 675840 and
        hash.md5(0,filesize) ==  "7ca54a11bf979832c19000d53874bb23"
}        
        
rule r0a4ef87b5ab1593121f3e3cfad9ea476 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.85 64bit (2018-03-06 10:05:33)"
        author = "@viql"
        date = "2018-03-26"
        sample = "0a4ef87b5ab1593121f3e3cfad9ea476"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 647168 and
        hash.md5(0,filesize) ==  "0a4ef87b5ab1593121f3e3cfad9ea476"
}        
        
rule rd957cda6190e8e04e7ed6d3cb8f79326 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.67 64bit (2017-10-12 23:32:10)"
        author = "@viql"
        date = "2018-03-26"
        sample = "d957cda6190e8e04e7ed6d3cb8f79326"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 466944 and
        hash.md5(0,filesize) ==  "d957cda6190e8e04e7ed6d3cb8f79326"
}        
        
rule r213861f6c38cf79771a4cc136474bf67 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.73 64bit (2017-11-16 15:02:36)"
        author = "@viql"
        date = "2018-03-26"
        sample = "213861f6c38cf79771a4cc136474bf67"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 471040 and
        hash.md5(0,filesize) ==  "213861f6c38cf79771a4cc136474bf67"
}        
        
rule r32b2e94cb2f7d4a71123b4f9585c63b3 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.85 32bit (2018-02-27 09:23:39)"
        author = "@viql"
        date = "2018-03-26"
        sample = "32b2e94cb2f7d4a71123b4f9585c63b3"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "32b2e94cb2f7d4a71123b4f9585c63b3"
}        
        
rule rad343e1aa8fb15c5cf04dd817fd3a1dd {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.68 32bit (2017-10-30 07:04:31)"
        author = "@viql"
        date = "2018-03-26"
        sample = "ad343e1aa8fb15c5cf04dd817fd3a1dd"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 360448 and
        hash.md5(0,filesize) ==  "ad343e1aa8fb15c5cf04dd817fd3a1dd"
}        
        
rule r537d5a22641f4816bb566cb505d084f6 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.85 32bit (2018-03-11 07:45:42)"
        author = "@viql"
        date = "2018-03-26"
        sample = "537d5a22641f4816bb566cb505d084f6"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 487424 and
        hash.md5(0,filesize) ==  "537d5a22641f4816bb566cb505d084f6"
}        
        
rule rd27b89048aee714e65f506bf744493d6 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.59 64bit (2017-06-26 06:06:22)"
        author = "@viql"
        date = "2018-03-26"
        sample = "d27b89048aee714e65f506bf744493d6"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 450560 and
        hash.md5(0,filesize) ==  "d27b89048aee714e65f506bf744493d6"
}        
        
rule rf93155d82bdbdd513f93106240b35b17 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.75 32bit (2017-12-04 07:37:40)"
        author = "@viql"
        date = "2018-03-26"
        sample = "f93155d82bdbdd513f93106240b35b17"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 352256 and
        hash.md5(0,filesize) ==  "f93155d82bdbdd513f93106240b35b17"
}        
        
rule r8bc3faf395280ce664c21bff1e019959 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.82 32bit (2018-02-15 15:18:22)"
        author = "@viql"
        date = "2018-03-26"
        sample = "8bc3faf395280ce664c21bff1e019959"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "8bc3faf395280ce664c21bff1e019959"
}        
        
rule r7ee2fbfee2623de1bc5b7ae3a0633891 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.85 64bit (2018-03-14 21:36:57)"
        author = "@viql"
        date = "2018-03-26"
        sample = "7ee2fbfee2623de1bc5b7ae3a0633891"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "7ee2fbfee2623de1bc5b7ae3a0633891"
}        
        
rule rb032f7854057613e856fa4c487c70c42 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.60 32bit (2017-07-17 07:30:28)"
        author = "@viql"
        date = "2018-03-26"
        sample = "b032f7854057613e856fa4c487c70c42"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 348160 and
        hash.md5(0,filesize) ==  "b032f7854057613e856fa4c487c70c42"
}        
        
rule r58692ccca8e32b7c7f48e76be001bfa0 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.67 32bit (2017-10-02 22:19:39)"
        author = "@viql"
        date = "2018-03-26"
        sample = "58692ccca8e32b7c7f48e76be001bfa0"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 331776 and
        hash.md5(0,filesize) ==  "58692ccca8e32b7c7f48e76be001bfa0"
}        
        
rule rd0436a7e50f39e42f00eee73a9ba7be6 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.65 64bit (2017-08-27 11:14:58)"
        author = "@viql"
        date = "2018-03-26"
        sample = "d0436a7e50f39e42f00eee73a9ba7be6"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 446464 and
        hash.md5(0,filesize) ==  "d0436a7e50f39e42f00eee73a9ba7be6"
}        
        
rule r85d3adf228524bb7bc6ea66d12ef18cd {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.85 32bit (2018-03-06 10:05:22)"
        author = "@viql"
        date = "2018-03-26"
        sample = "85d3adf228524bb7bc6ea66d12ef18cd"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "85d3adf228524bb7bc6ea66d12ef18cd"
}        
        
rule rf441b8d2f70ef84e8cc71556f293ff7a {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.80 64bit (2017-12-22 22:29:34)"
        author = "@viql"
        date = "2018-03-26"
        sample = "f441b8d2f70ef84e8cc71556f293ff7a"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 471040 and
        hash.md5(0,filesize) ==  "f441b8d2f70ef84e8cc71556f293ff7a"
}        
        
rule r011687661ecc9673141e8ffafb7004af {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.82 64bit (2018-02-05 09:28:13)"
        author = "@viql"
        date = "2018-03-26"
        sample = "011687661ecc9673141e8ffafb7004af"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 753664 and
        hash.md5(0,filesize) ==  "011687661ecc9673141e8ffafb7004af"
}        
        
rule r964e6212ab22e166a343f5417514f62d {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.83 32bit (2018-02-16 07:12:54)"
        author = "@viql"
        date = "2018-03-26"
        sample = "964e6212ab22e166a343f5417514f62d"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 491520 and
        hash.md5(0,filesize) ==  "964e6212ab22e166a343f5417514f62d"
}        
        
rule rfa593738687c4de41562e962fb4ca9c1 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.77 64bit (2017-12-08 20:44:40)"
        author = "@viql"
        date = "2018-03-26"
        sample = "fa593738687c4de41562e962fb4ca9c1"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 475136 and
        hash.md5(0,filesize) ==  "fa593738687c4de41562e962fb4ca9c1"
}        
        
rule rf520c0c589a255df597f240c37837f81 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.65 32bit (2017-08-27 11:13:34)"
        author = "@viql"
        date = "2018-03-26"
        sample = "f520c0c589a255df597f240c37837f81"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 331776 and
        hash.md5(0,filesize) ==  "f520c0c589a255df597f240c37837f81"
}        
        
rule r4e6c207f0f069934b8da7fa48c235a44 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.68 64bit (2017-10-20 15:55:07)"
        author = "@viql"
        date = "2018-03-26"
        sample = "4e6c207f0f069934b8da7fa48c235a44"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 446464 and
        hash.md5(0,filesize) ==  "4e6c207f0f069934b8da7fa48c235a44"
}        
        
rule rd819d6785b313258f4434b5e3db7b268 {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.85 32bit (2018-03-23 18:13:27)"
        author = "@viql"
        date = "2018-03-26"
        sample = "d819d6785b313258f4434b5e3db7b268"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "d819d6785b313258f4434b5e3db7b268"
}        
        
rule r3df2e31681a7e529139a9fed7f733ad6 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.62 64bit (2017-08-20 16:03:51)"
        author = "@viql"
        date = "2018-03-26"
        sample = "3df2e31681a7e529139a9fed7f733ad6"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 454656 and
        hash.md5(0,filesize) ==  "3df2e31681a7e529139a9fed7f733ad6"
}        
        
rule rce82508dece9d26ce3fb84ea826a9eff {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.68 32bit (2017-10-20 15:54:32)"
        author = "@viql"
        date = "2018-03-26"
        sample = "ce82508dece9d26ce3fb84ea826a9eff"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 356352 and
        hash.md5(0,filesize) ==  "ce82508dece9d26ce3fb84ea826a9eff"
}        
        
rule rba191e35a260f6d106ccbe82a10aa5cc {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.73 32bit (2017-11-16 15:02:24)"
        author = "@viql"
        date = "2018-03-26"
        sample = "ba191e35a260f6d106ccbe82a10aa5cc"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 352256 and
        hash.md5(0,filesize) ==  "ba191e35a260f6d106ccbe82a10aa5cc"
}        
        
rule rcffb11367fa1833d4b8fd74fc3b48f06 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.80 64bit (2017-12-16 13:23:00)"
        author = "@viql"
        date = "2018-03-26"
        sample = "cffb11367fa1833d4b8fd74fc3b48f06"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 471040 and
        hash.md5(0,filesize) ==  "cffb11367fa1833d4b8fd74fc3b48f06"
}        
        
rule ra0e62320c474e6df73fc032686e6c97e {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.74 64bit (2017-11-21 13:52:04)"
        author = "@viql"
        date = "2018-03-26"
        sample = "a0e62320c474e6df73fc032686e6c97e"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 466944 and
        hash.md5(0,filesize) ==  "a0e62320c474e6df73fc032686e6c97e"
}        
        
rule r20cb606139fa6f13b87b32997dc5aa95 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.62 64bit (2017-08-12 22:22:06)"
        author = "@viql"
        date = "2018-03-26"
        sample = "20cb606139fa6f13b87b32997dc5aa95"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 454656 and
        hash.md5(0,filesize) ==  "20cb606139fa6f13b87b32997dc5aa95"
}        
        
rule r3fa18db246e3766ca221858e44d4a0fc {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.82 32bit (2018-02-05 09:23:23)"
        author = "@viql"
        date = "2018-03-26"
        sample = "3fa18db246e3766ca221858e44d4a0fc"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "3fa18db246e3766ca221858e44d4a0fc"
}        
        
rule rdcf43e6642171ac71b4664846636e5dd {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.75 64bit (2017-12-04 07:37:53)"
        author = "@viql"
        date = "2018-03-26"
        sample = "dcf43e6642171ac71b4664846636e5dd"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 475136 and
        hash.md5(0,filesize) ==  "dcf43e6642171ac71b4664846636e5dd"
}        
        
rule r1264dbcf9106b7adab3682b9b42bdfcf {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.80 64bit (2018-01-18 13:04:13)"
        author = "@viql"
        date = "2018-03-26"
        sample = "1264dbcf9106b7adab3682b9b42bdfcf"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 757760 and
        hash.md5(0,filesize) ==  "1264dbcf9106b7adab3682b9b42bdfcf"
}        
        
rule rde6425b9b266455b8009129085f99117 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.85 32bit (2018-03-23 18:14:41)"
        author = "@viql"
        date = "2018-03-26"
        sample = "de6425b9b266455b8009129085f99117"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "de6425b9b266455b8009129085f99117"
}        
        
rule ra05c5b9f11453fc8090e2d2d9d73d4c0 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.62 32bit (2017-08-12 22:21:54)"
        author = "@viql"
        date = "2018-03-26"
        sample = "a05c5b9f11453fc8090e2d2d9d73d4c0"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 331776 and
        hash.md5(0,filesize) ==  "a05c5b9f11453fc8090e2d2d9d73d4c0"
}        
        
rule r306b584f2b6189699b9597a14734fa95 {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.85 32bit (2018-03-11 07:48:14)"
        author = "@viql"
        date = "2018-03-26"
        sample = "306b584f2b6189699b9597a14734fa95"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "306b584f2b6189699b9597a14734fa95"
}        
        
rule re12b7bbb65aa0b1c1d63c3ebd59ad115 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.85 64bit (2018-03-11 07:22:01)"
        author = "@viql"
        date = "2018-03-26"
        sample = "e12b7bbb65aa0b1c1d63c3ebd59ad115"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "e12b7bbb65aa0b1c1d63c3ebd59ad115"
}        
        
rule r5705837474d6126e8e0781b1656e7415 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.62 32bit (2017-08-03 20:32:06)"
        author = "@viql"
        date = "2018-03-26"
        sample = "5705837474d6126e8e0781b1656e7415"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 352256 and
        hash.md5(0,filesize) ==  "5705837474d6126e8e0781b1656e7415"
}        
        
rule r93bfdb5b9810387f1769a6f76461f550 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.85 32bit (2018-03-11 07:21:42)"
        author = "@viql"
        date = "2018-03-26"
        sample = "93bfdb5b9810387f1769a6f76461f550"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "93bfdb5b9810387f1769a6f76461f550"
}        
        
rule rb62d54c8bd2c2d6b6b2a6cf81b0fb097 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.61 64bit (2017-07-31 21:36:25)"
        author = "@viql"
        date = "2018-03-26"
        sample = "b62d54c8bd2c2d6b6b2a6cf81b0fb097"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 450560 and
        hash.md5(0,filesize) ==  "b62d54c8bd2c2d6b6b2a6cf81b0fb097"
}        
        
rule red570695236713a847a81fb62e54f782 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.74 32bit (2017-11-25 13:14:38)"
        author = "@viql"
        date = "2018-03-26"
        sample = "ed570695236713a847a81fb62e54f782"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 348160 and
        hash.md5(0,filesize) ==  "ed570695236713a847a81fb62e54f782"
}        
        
rule r14aa615a9be3edc86e12f6fa6ac0b154 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.61 32bit (2017-07-31 21:36:04)"
        author = "@viql"
        date = "2018-03-26"
        sample = "14aa615a9be3edc86e12f6fa6ac0b154"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 331776 and
        hash.md5(0,filesize) ==  "14aa615a9be3edc86e12f6fa6ac0b154"
}        
        
rule r4823da9b1fa44bf06b5a1dfcf52ee03e {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.66 32bit (2017-09-10 16:17:16)"
        author = "@viql"
        date = "2018-03-26"
        sample = "4823da9b1fa44bf06b5a1dfcf52ee03e"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 335872 and
        hash.md5(0,filesize) ==  "4823da9b1fa44bf06b5a1dfcf52ee03e"
}        
        
rule r879d3069145d6276f2a1cb8135f4078a {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.85 32bit (2018-03-14 21:36:42)"
        author = "@viql"
        date = "2018-03-26"
        sample = "879d3069145d6276f2a1cb8135f4078a"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "879d3069145d6276f2a1cb8135f4078a"
}        
        
rule r033d7486b43935a8adf5796835d088d4 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.85 64bit (2018-03-23 18:14:53)"
        author = "@viql"
        date = "2018-03-26"
        sample = "033d7486b43935a8adf5796835d088d4"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "033d7486b43935a8adf5796835d088d4"
}        
        
rule r6683059357268d4a28ea8f4adb587ef5 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.68 32bit (2017-10-24 05:15:11)"
        author = "@viql"
        date = "2018-03-26"
        sample = "6683059357268d4a28ea8f4adb587ef5"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 356352 and
        hash.md5(0,filesize) ==  "6683059357268d4a28ea8f4adb587ef5"
}        
        
rule r491cb5e246e51c01d30840ce75a7a8fb {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.83 64bit (2018-02-16 07:07:38)"
        author = "@viql"
        date = "2018-03-26"
        sample = "491cb5e246e51c01d30840ce75a7a8fb"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 692224 and
        hash.md5(0,filesize) ==  "491cb5e246e51c01d30840ce75a7a8fb"
}        
        
rule r0f676b95ae81e27ae286194fc2c90fb6 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.61 32bit (2017-07-25 16:30:40)"
        author = "@viql"
        date = "2018-03-26"
        sample = "0f676b95ae81e27ae286194fc2c90fb6"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 331776 and
        hash.md5(0,filesize) ==  "0f676b95ae81e27ae286194fc2c90fb6"
}        
        
rule ra8d7b2014fa44252967635c15f8cab50 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.85 64bit (2018-03-20 09:35:23)"
        author = "@viql"
        date = "2018-03-26"
        sample = "a8d7b2014fa44252967635c15f8cab50"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 643072 and
        hash.md5(0,filesize) ==  "a8d7b2014fa44252967635c15f8cab50"
}        
        
rule r4796d47eb1ae2c03c98d31c4bb9e7327 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.83 64bit (2018-02-16 07:10:56)"
        author = "@viql"
        date = "2018-03-26"
        sample = "4796d47eb1ae2c03c98d31c4bb9e7327"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 684032 and
        hash.md5(0,filesize) ==  "4796d47eb1ae2c03c98d31c4bb9e7327"
}        
        
rule r1daa6d0c122f78d2069b5df536e26508 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.60 64bit (2017-06-28 21:58:25)"
        author = "@viql"
        date = "2018-03-26"
        sample = "1daa6d0c122f78d2069b5df536e26508"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 450560 and
        hash.md5(0,filesize) ==  "1daa6d0c122f78d2069b5df536e26508"
}        
        
rule r44d7924d72eb125d71d194415f585016 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.80 32bit (2017-12-22 22:29:19)"
        author = "@viql"
        date = "2018-03-26"
        sample = "44d7924d72eb125d71d194415f585016"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 352256 and
        hash.md5(0,filesize) ==  "44d7924d72eb125d71d194415f585016"
}        
        
rule r8cfa2bc7ce6cc76fb7252392d29e9a21 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.66 32bit (2017-09-18 05:13:00)"
        author = "@viql"
        date = "2018-03-26"
        sample = "8cfa2bc7ce6cc76fb7252392d29e9a21"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 348160 and
        hash.md5(0,filesize) ==  "8cfa2bc7ce6cc76fb7252392d29e9a21"
}        
        
rule r67290af5a4d60537720e54a4fc6b4d97 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.62 64bit (2017-08-03 20:33:08)"
        author = "@viql"
        date = "2018-03-26"
        sample = "67290af5a4d60537720e54a4fc6b4d97"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 466944 and
        hash.md5(0,filesize) ==  "67290af5a4d60537720e54a4fc6b4d97"
}        
        
rule rceeb0c36d1eeb5f35f82ddd3bce58716 {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.85 64bit (2018-03-23 18:13:54)"
        author = "@viql"
        date = "2018-03-26"
        sample = "ceeb0c36d1eeb5f35f82ddd3bce58716"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "ceeb0c36d1eeb5f35f82ddd3bce58716"
}        
        
rule r1fbbcd16d07fa55c40db393e0916dd1c {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.61 64bit (2017-07-25 16:27:55)"
        author = "@viql"
        date = "2018-03-26"
        sample = "1fbbcd16d07fa55c40db393e0916dd1c"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 450560 and
        hash.md5(0,filesize) ==  "1fbbcd16d07fa55c40db393e0916dd1c"
}        
        
rule r70b71d97bcd65b27c7e6f44797672318 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.82 32bit (2018-02-14 09:16:41)"
        author = "@viql"
        date = "2018-03-26"
        sample = "70b71d97bcd65b27c7e6f44797672318"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 487424 and
        hash.md5(0,filesize) ==  "70b71d97bcd65b27c7e6f44797672318"
}        
        
rule r6b68cb8768d8c6a0badcd1bbdafb8af7 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.85 32bit (2018-03-06 22:04:31)"
        author = "@viql"
        date = "2018-03-26"
        sample = "6b68cb8768d8c6a0badcd1bbdafb8af7"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 487424 and
        hash.md5(0,filesize) ==  "6b68cb8768d8c6a0badcd1bbdafb8af7"
}        
        
rule ra58cbf4866ceb2e86e839970cd684328 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.60 32bit (2017-07-09 17:02:02)"
        author = "@viql"
        date = "2018-03-26"
        sample = "a58cbf4866ceb2e86e839970cd684328"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 335872 and
        hash.md5(0,filesize) ==  "a58cbf4866ceb2e86e839970cd684328"
}        
        
rule r2415a6f409c9572f7eda4ba789359c56 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.74 64bit (2017-11-25 13:14:49)"
        author = "@viql"
        date = "2018-03-26"
        sample = "2415a6f409c9572f7eda4ba789359c56"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "2415a6f409c9572f7eda4ba789359c56"
}        
        
rule r996c8c52b5aa9626cbbff991d86ced57 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.68 64bit (2017-10-24 05:15:49)"
        author = "@viql"
        date = "2018-03-26"
        sample = "996c8c52b5aa9626cbbff991d86ced57"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 446464 and
        hash.md5(0,filesize) ==  "996c8c52b5aa9626cbbff991d86ced57"
}        
        
rule reeace3e72424b8c3592bca8ecb32555d {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.72 64bit (2017-11-16 10:49:31)"
        author = "@viql"
        date = "2018-03-26"
        sample = "eeace3e72424b8c3592bca8ecb32555d"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 466944 and
        hash.md5(0,filesize) ==  "eeace3e72424b8c3592bca8ecb32555d"
}        
        
rule rd053911bbc6865377eb70720aa4c4d4d {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.83 64bit (2018-02-16 07:13:10)"
        author = "@viql"
        date = "2018-03-26"
        sample = "d053911bbc6865377eb70720aa4c4d4d"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 684032 and
        hash.md5(0,filesize) ==  "d053911bbc6865377eb70720aa4c4d4d"
}        
        
rule r1af43327df1853278496baa53190380b {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.59 32bit (2017-06-26 06:04:50)"
        author = "@viql"
        date = "2018-03-26"
        sample = "1af43327df1853278496baa53190380b"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 335872 and
        hash.md5(0,filesize) ==  "1af43327df1853278496baa53190380b"
}        
        
rule rb773caf389f2da2e4aeadc1f9fd69b2a {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.85 32bit (2018-03-11 07:21:42)"
        author = "@viql"
        date = "2018-03-26"
        sample = "b773caf389f2da2e4aeadc1f9fd69b2a"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "b773caf389f2da2e4aeadc1f9fd69b2a"
}        
        
rule r66034294e67c0465453fc080b22ae76a {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.83 32bit (2018-02-16 07:10:44)"
        author = "@viql"
        date = "2018-03-26"
        sample = "66034294e67c0465453fc080b22ae76a"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 491520 and
        hash.md5(0,filesize) ==  "66034294e67c0465453fc080b22ae76a"
}        
        
rule rba9472537e6404849dddf9341d155928 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.85 64bit (2018-03-06 22:04:42)"
        author = "@viql"
        date = "2018-03-26"
        sample = "ba9472537e6404849dddf9341d155928"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 643072 and
        hash.md5(0,filesize) ==  "ba9472537e6404849dddf9341d155928"
}        
        
