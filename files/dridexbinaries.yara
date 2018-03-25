import "hash"

rule r3fa18db246e3766ca221858e44d4a0fc {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.82 32bit (2018-02-05 09:23:23)"
        author = "@viql"
        date = "2018-03-25"
        sample = "3fa18db246e3766ca221858e44d4a0fc"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "3fa18db246e3766ca221858e44d4a0fc"
}        
        
rule r32ac659d0f4233bc4bf98ada3f550406 {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.82 64bit (2018-02-05 09:24:10)"
        author = "@viql"
        date = "2018-03-25"
        sample = "32ac659d0f4233bc4bf98ada3f550406"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 753664 and
        hash.md5(0,filesize) ==  "32ac659d0f4233bc4bf98ada3f550406"
}        
        
rule rd819d6785b313258f4434b5e3db7b268 {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.85 32bit (2018-03-23 18:13:27)"
        author = "@viql"
        date = "2018-03-25"
        sample = "d819d6785b313258f4434b5e3db7b268"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "d819d6785b313258f4434b5e3db7b268"
}        
        
rule r306b584f2b6189699b9597a14734fa95 {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.85 32bit (2018-03-11 07:48:14)"
        author = "@viql"
        date = "2018-03-25"
        sample = "306b584f2b6189699b9597a14734fa95"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "306b584f2b6189699b9597a14734fa95"
}        
        
rule rf41fb1019007c5e03ff3d38ee91523dd {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.85 64bit (2018-03-11 07:48:28)"
        author = "@viql"
        date = "2018-03-25"
        sample = "f41fb1019007c5e03ff3d38ee91523dd"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "f41fb1019007c5e03ff3d38ee91523dd"
}        
        
rule rdf80d463f19b61f2bc10622e2172fd36 {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.85 64bit (2018-03-11 07:48:28)"
        author = "@viql"
        date = "2018-03-25"
        sample = "df80d463f19b61f2bc10622e2172fd36"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "df80d463f19b61f2bc10622e2172fd36"
}        
        
rule rceeb0c36d1eeb5f35f82ddd3bce58716 {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.85 64bit (2018-03-23 18:13:54)"
        author = "@viql"
        date = "2018-03-25"
        sample = "ceeb0c36d1eeb5f35f82ddd3bce58716"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "ceeb0c36d1eeb5f35f82ddd3bce58716"
}        
        
rule rd053911bbc6865377eb70720aa4c4d4d {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.83 64bit (2018-02-16 07:13:10)"
        author = "@viql"
        date = "2018-03-25"
        sample = "d053911bbc6865377eb70720aa4c4d4d"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 684032 and
        hash.md5(0,filesize) ==  "d053911bbc6865377eb70720aa4c4d4d"
}        
        
rule r3113f7ca01b174211eae1a3a8f1614df {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.85 32bit (2018-03-11 07:48:14)"
        author = "@viql"
        date = "2018-03-25"
        sample = "3113f7ca01b174211eae1a3a8f1614df"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "3113f7ca01b174211eae1a3a8f1614df"
}        
        
rule r964e6212ab22e166a343f5417514f62d {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.83 32bit (2018-02-16 07:12:54)"
        author = "@viql"
        date = "2018-03-25"
        sample = "964e6212ab22e166a343f5417514f62d"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 491520 and
        hash.md5(0,filesize) ==  "964e6212ab22e166a343f5417514f62d"
}        
        
