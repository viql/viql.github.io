import "hash"

rule r44d7924d72eb125d71d194415f585016 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.80 32bit (2017-12-22 22:29:19)"
        author = "@viql"
        date = "2018-07-19"
        sample = "44d7924d72eb125d71d194415f585016"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 352256 and
        hash.md5(0,filesize) ==  "44d7924d72eb125d71d194415f585016"
}        
        
rule r6683059357268d4a28ea8f4adb587ef5 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.68 32bit (2017-10-24 05:15:11)"
        author = "@viql"
        date = "2018-07-19"
        sample = "6683059357268d4a28ea8f4adb587ef5"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 356352 and
        hash.md5(0,filesize) ==  "6683059357268d4a28ea8f4adb587ef5"
}        
        
rule r86afe888da74886b3f77521c383dc95a {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' 32bit (2018-06-15 09:01:06)"
        author = "@viql"
        date = "2018-07-19"
        sample = "86afe888da74886b3f77521c383dc95a"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 507904 and
        hash.md5(0,filesize) ==  "86afe888da74886b3f77521c383dc95a"
}        
        
rule rb7e06885887b3ac39fae6e931bdf22cc {
    meta:
        description = "Dridex module: Botnet 7200, module 'bot' version 4.87 64bit (2018-06-11 12:25:18)"
        author = "@viql"
        date = "2018-07-19"
        sample = "b7e06885887b3ac39fae6e931bdf22cc"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 626688 and
        hash.md5(0,filesize) ==  "b7e06885887b3ac39fae6e931bdf22cc"
}        
        
rule r3c3d6fa2f3c8ad96e6f4cfd381df852c {
    meta:
        description = "Dridex module: Botnet 7200, module 'bot' 32bit (2018-06-25 14:19:27)"
        author = "@viql"
        date = "2018-07-19"
        sample = "3c3d6fa2f3c8ad96e6f4cfd381df852c"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 507904 and
        hash.md5(0,filesize) ==  "3c3d6fa2f3c8ad96e6f4cfd381df852c"
}        
        
rule rcc7e2f70a966f286723c8009ba55f853 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.60 32bit (2017-06-28 21:58:14)"
        author = "@viql"
        date = "2018-07-19"
        sample = "cc7e2f70a966f286723c8009ba55f853"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 339968 and
        hash.md5(0,filesize) ==  "cc7e2f70a966f286723c8009ba55f853"
}        
        
rule reeace3e72424b8c3592bca8ecb32555d {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.72 64bit (2017-11-16 10:49:31)"
        author = "@viql"
        date = "2018-07-19"
        sample = "eeace3e72424b8c3592bca8ecb32555d"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 466944 and
        hash.md5(0,filesize) ==  "eeace3e72424b8c3592bca8ecb32555d"
}        
        
rule re7172aadda00497ce11527fe0153132c {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.85 64bit (2018-05-01 14:43:04)"
        author = "@viql"
        date = "2018-07-19"
        sample = "e7172aadda00497ce11527fe0153132c"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 647168 and
        hash.md5(0,filesize) ==  "e7172aadda00497ce11527fe0153132c"
}        
        
rule rc49cbfdcb4fcc5096462e9f24c5d1dff {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' version 4.14 64bit (2018-06-11 12:25:18)"
        author = "@viql"
        date = "2018-07-19"
        sample = "c49cbfdcb4fcc5096462e9f24c5d1dff"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 626688 and
        hash.md5(0,filesize) ==  "c49cbfdcb4fcc5096462e9f24c5d1dff"
}        
        
rule rb032f7854057613e856fa4c487c70c42 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.60 32bit (2017-07-17 07:30:28)"
        author = "@viql"
        date = "2018-07-19"
        sample = "b032f7854057613e856fa4c487c70c42"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 348160 and
        hash.md5(0,filesize) ==  "b032f7854057613e856fa4c487c70c42"
}        
        
rule redba64cb2157ddb77cb33cc428a48076 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.77 32bit (2017-12-08 20:44:29)"
        author = "@viql"
        date = "2018-07-19"
        sample = "edba64cb2157ddb77cb33cc428a48076"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 352256 and
        hash.md5(0,filesize) ==  "edba64cb2157ddb77cb33cc428a48076"
}        
        
rule r5cb82acf05b86fe16953ff4a1c412a97 {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' version 4.86 64bit (2018-05-30 12:17:53)"
        author = "@viql"
        date = "2018-07-19"
        sample = "5cb82acf05b86fe16953ff4a1c412a97"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 659456 and
        hash.md5(0,filesize) ==  "5cb82acf05b86fe16953ff4a1c412a97"
}        
        
rule r8c278fd7ef8059ef6ae7edd7acff8954 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.86 64bit (2018-05-31 12:08:30)"
        author = "@viql"
        date = "2018-07-19"
        sample = "8c278fd7ef8059ef6ae7edd7acff8954"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 643072 and
        hash.md5(0,filesize) ==  "8c278fd7ef8059ef6ae7edd7acff8954"
}        
        
rule rfa54d7c3e7740385cdb1d286e29a598e {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' version 4.86 64bit (2018-05-25 13:38:13)"
        author = "@viql"
        date = "2018-07-19"
        sample = "fa54d7c3e7740385cdb1d286e29a598e"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 659456 and
        hash.md5(0,filesize) ==  "fa54d7c3e7740385cdb1d286e29a598e"
}        
        
rule r4fb3774f18c9400bd7fda15cae271e5a {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.14 64bit (2018-06-07 12:14:07)"
        author = "@viql"
        date = "2018-07-19"
        sample = "4fb3774f18c9400bd7fda15cae271e5a"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "4fb3774f18c9400bd7fda15cae271e5a"
}        
        
rule r6f53a6a36b757eb843b81cbc82e81f34 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.86 64bit (2018-06-06 12:00:27)"
        author = "@viql"
        date = "2018-07-19"
        sample = "6f53a6a36b757eb843b81cbc82e81f34"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 638976 and
        hash.md5(0,filesize) ==  "6f53a6a36b757eb843b81cbc82e81f34"
}        
        
rule rfa593738687c4de41562e962fb4ca9c1 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.77 64bit (2017-12-08 20:44:40)"
        author = "@viql"
        date = "2018-07-19"
        sample = "fa593738687c4de41562e962fb4ca9c1"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 475136 and
        hash.md5(0,filesize) ==  "fa593738687c4de41562e962fb4ca9c1"
}        
        
rule ra73472db9c92acf93a9ee96e3335912b {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' version 4.85 32bit (2018-04-27 15:22:32)"
        author = "@viql"
        date = "2018-07-19"
        sample = "a73472db9c92acf93a9ee96e3335912b"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 548864 and
        hash.md5(0,filesize) ==  "a73472db9c92acf93a9ee96e3335912b"
}        
        
rule rce82508dece9d26ce3fb84ea826a9eff {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.68 32bit (2017-10-20 15:54:32)"
        author = "@viql"
        date = "2018-07-19"
        sample = "ce82508dece9d26ce3fb84ea826a9eff"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 356352 and
        hash.md5(0,filesize) ==  "ce82508dece9d26ce3fb84ea826a9eff"
}        
        
rule ra0de22f3b01556deeae2c90a690b5845 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.68 64bit (2017-10-18 11:34:02)"
        author = "@viql"
        date = "2018-07-19"
        sample = "a0de22f3b01556deeae2c90a690b5845"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 446464 and
        hash.md5(0,filesize) ==  "a0de22f3b01556deeae2c90a690b5845"
}        
        
rule rcc8ab8cafcd225ed4ebc70e0139b6890 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.85 64bit (2018-03-20 09:35:23)"
        author = "@viql"
        date = "2018-07-19"
        sample = "cc8ab8cafcd225ed4ebc70e0139b6890"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 643072 and
        hash.md5(0,filesize) ==  "cc8ab8cafcd225ed4ebc70e0139b6890"
}        
        
rule ra3a8e607a5f905928c777844e47b5f9a {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' version 4.14 32bit (2018-06-11 12:24:30)"
        author = "@viql"
        date = "2018-07-19"
        sample = "a3a8e607a5f905928c777844e47b5f9a"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 512000 and
        hash.md5(0,filesize) ==  "a3a8e607a5f905928c777844e47b5f9a"
}        
        
rule rdcf43e6642171ac71b4664846636e5dd {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.75 64bit (2017-12-04 07:37:53)"
        author = "@viql"
        date = "2018-07-19"
        sample = "dcf43e6642171ac71b4664846636e5dd"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 475136 and
        hash.md5(0,filesize) ==  "dcf43e6642171ac71b4664846636e5dd"
}        
        
rule ra05c5b9f11453fc8090e2d2d9d73d4c0 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.62 32bit (2017-08-12 22:21:54)"
        author = "@viql"
        date = "2018-07-19"
        sample = "a05c5b9f11453fc8090e2d2d9d73d4c0"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 331776 and
        hash.md5(0,filesize) ==  "a05c5b9f11453fc8090e2d2d9d73d4c0"
}        
        
rule re499b41403337ae51cb2a7c23b14e175 {
    meta:
        description = "Dridex module: Botnet 7200, module 'bot' version 4.86 64bit (2018-05-30 11:11:22)"
        author = "@viql"
        date = "2018-07-19"
        sample = "e499b41403337ae51cb2a7c23b14e175"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 659456 and
        hash.md5(0,filesize) ==  "e499b41403337ae51cb2a7c23b14e175"
}        
        
rule r75990b40f65803028af152dacfb513a1 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.86 32bit (2018-06-01 18:28:04)"
        author = "@viql"
        date = "2018-07-19"
        sample = "75990b40f65803028af152dacfb513a1"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 507904 and
        hash.md5(0,filesize) ==  "75990b40f65803028af152dacfb513a1"
}        
        
rule rb63214353184663530521e41f1452078 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.71 32bit (2017-11-08 12:31:10)"
        author = "@viql"
        date = "2018-07-19"
        sample = "b63214353184663530521e41f1452078"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 348160 and
        hash.md5(0,filesize) ==  "b63214353184663530521e41f1452078"
}        
        
rule r70b71d97bcd65b27c7e6f44797672318 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.82 32bit (2018-02-14 09:16:41)"
        author = "@viql"
        date = "2018-07-19"
        sample = "70b71d97bcd65b27c7e6f44797672318"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 487424 and
        hash.md5(0,filesize) ==  "70b71d97bcd65b27c7e6f44797672318"
}        
        
rule r1c1b388ffcc6a971be99e3b84171d1c0 {
    meta:
        description = "Dridex module: Botnet 10105, module 'bot' version 2.22 32bit (2018-06-17 11:00:00)"
        author = "@viql"
        date = "2018-07-19"
        sample = "1c1b388ffcc6a971be99e3b84171d1c0"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 577536 and
        hash.md5(0,filesize) ==  "1c1b388ffcc6a971be99e3b84171d1c0"
}        
        
rule rc32270515d30840b42445e5ff64e97a9 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' 32bit (2018-05-30 14:40:32)"
        author = "@viql"
        date = "2018-07-19"
        sample = "c32270515d30840b42445e5ff64e97a9"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 528384 and
        hash.md5(0,filesize) ==  "c32270515d30840b42445e5ff64e97a9"
}        
        
rule ra0e62320c474e6df73fc032686e6c97e {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.74 64bit (2017-11-21 13:52:04)"
        author = "@viql"
        date = "2018-07-19"
        sample = "a0e62320c474e6df73fc032686e6c97e"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 466944 and
        hash.md5(0,filesize) ==  "a0e62320c474e6df73fc032686e6c97e"
}        
        
rule rb2555356e1695a975b8fbd75d1be73ac {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' version 4.85 64bit (2018-03-23 18:14:53)"
        author = "@viql"
        date = "2018-07-19"
        sample = "b2555356e1695a975b8fbd75d1be73ac"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "b2555356e1695a975b8fbd75d1be73ac"
}        
        
rule r747b19636ece96cc1f2b70772f71cbe3 {
    meta:
        description = "Dridex module: Botnet 10105, module 'bot' version 2.20 32bit (2018-06-05 07:42:29)"
        author = "@viql"
        date = "2018-07-19"
        sample = "747b19636ece96cc1f2b70772f71cbe3"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 565248 and
        hash.md5(0,filesize) ==  "747b19636ece96cc1f2b70772f71cbe3"
}        
        
rule r383d4d582ae31a5bcca5fbef4068c61c {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.60 64bit (2017-07-17 07:30:52)"
        author = "@viql"
        date = "2018-07-19"
        sample = "383d4d582ae31a5bcca5fbef4068c61c"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 462848 and
        hash.md5(0,filesize) ==  "383d4d582ae31a5bcca5fbef4068c61c"
}        
        
rule r39a1d5c2e00b4dd5a9547d62bfe2f457 {
    meta:
        description = "Dridex module: Botnet 10105, module 'bot' version 2.22 64bit (2018-06-11 09:30:25)"
        author = "@viql"
        date = "2018-07-19"
        sample = "39a1d5c2e00b4dd5a9547d62bfe2f457"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 716800 and
        hash.md5(0,filesize) ==  "39a1d5c2e00b4dd5a9547d62bfe2f457"
}        
        
rule rf520c0c589a255df597f240c37837f81 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.65 32bit (2017-08-27 11:13:34)"
        author = "@viql"
        date = "2018-07-19"
        sample = "f520c0c589a255df597f240c37837f81"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 331776 and
        hash.md5(0,filesize) ==  "f520c0c589a255df597f240c37837f81"
}        
        
rule r6650a83efe4719129cac32f06e8765c2 {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' version 4.86 32bit (2018-05-29 11:39:42)"
        author = "@viql"
        date = "2018-07-19"
        sample = "6650a83efe4719129cac32f06e8765c2"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 520192 and
        hash.md5(0,filesize) ==  "6650a83efe4719129cac32f06e8765c2"
}        
        
rule ra40ba82daea1dce261b2231d2eb8fd70 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.80 32bit (2018-01-18 13:04:02)"
        author = "@viql"
        date = "2018-07-19"
        sample = "a40ba82daea1dce261b2231d2eb8fd70"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "a40ba82daea1dce261b2231d2eb8fd70"
}        
        
rule ra889fc46b4eed4a031343706ea731157 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.82 64bit (2018-02-15 15:18:43)"
        author = "@viql"
        date = "2018-07-19"
        sample = "a889fc46b4eed4a031343706ea731157"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 647168 and
        hash.md5(0,filesize) ==  "a889fc46b4eed4a031343706ea731157"
}        
        
rule rc42a6fee5b7446a087e7226d8754eb06 {
    meta:
        description = "Dridex module: Botnet 7200, module 'bot' version 4.14 64bit (2018-06-07 14:15:20)"
        author = "@viql"
        date = "2018-07-19"
        sample = "c42a6fee5b7446a087e7226d8754eb06"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "c42a6fee5b7446a087e7226d8754eb06"
}        
        
rule r3fa18db246e3766ca221858e44d4a0fc {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.82 32bit (2018-02-05 09:23:23)"
        author = "@viql"
        date = "2018-07-19"
        sample = "3fa18db246e3766ca221858e44d4a0fc"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "3fa18db246e3766ca221858e44d4a0fc"
}        
        
rule r9bc379ffa93c47f312d17f3278624fff {
    meta:
        description = "Dridex module: Botnet 7200, module 'bot' 64bit (2018-07-16 09:22:18)"
        author = "@viql"
        date = "2018-07-19"
        sample = "9bc379ffa93c47f312d17f3278624fff"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "9bc379ffa93c47f312d17f3278624fff"
}        
        
rule r76382ab7b72cf3e1244640ed0461c7aa {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' version 4.86 64bit (2018-06-06 12:00:27)"
        author = "@viql"
        date = "2018-07-19"
        sample = "76382ab7b72cf3e1244640ed0461c7aa"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 638976 and
        hash.md5(0,filesize) ==  "76382ab7b72cf3e1244640ed0461c7aa"
}        
        
rule ra58cbf4866ceb2e86e839970cd684328 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.60 32bit (2017-07-09 17:02:02)"
        author = "@viql"
        date = "2018-07-19"
        sample = "a58cbf4866ceb2e86e839970cd684328"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 335872 and
        hash.md5(0,filesize) ==  "a58cbf4866ceb2e86e839970cd684328"
}        
        
rule r14aa615a9be3edc86e12f6fa6ac0b154 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.61 32bit (2017-07-31 21:36:04)"
        author = "@viql"
        date = "2018-07-19"
        sample = "14aa615a9be3edc86e12f6fa6ac0b154"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 331776 and
        hash.md5(0,filesize) ==  "14aa615a9be3edc86e12f6fa6ac0b154"
}        
        
rule r4e6c207f0f069934b8da7fa48c235a44 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.68 64bit (2017-10-20 15:55:07)"
        author = "@viql"
        date = "2018-07-19"
        sample = "4e6c207f0f069934b8da7fa48c235a44"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 446464 and
        hash.md5(0,filesize) ==  "4e6c207f0f069934b8da7fa48c235a44"
}        
        
rule r2edc6e7e2c7a8968ae4cfb9d6f6f09c7 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' 32bit (2018-06-15 09:01:06)"
        author = "@viql"
        date = "2018-07-19"
        sample = "2edc6e7e2c7a8968ae4cfb9d6f6f09c7"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 507904 and
        hash.md5(0,filesize) ==  "2edc6e7e2c7a8968ae4cfb9d6f6f09c7"
}        
        
rule rf6ec84374c1effa56e7bf12499318c5d {
    meta:
        description = "Dridex module: Botnet 10105, module 'bot' 32bit (2018-06-21 09:42:24)"
        author = "@viql"
        date = "2018-07-19"
        sample = "f6ec84374c1effa56e7bf12499318c5d"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 512000 and
        hash.md5(0,filesize) ==  "f6ec84374c1effa56e7bf12499318c5d"
}        
        
rule r037df38bd30a08ac4f8bff53a33070b8 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' 32bit (2018-06-11 12:24:30)"
        author = "@viql"
        date = "2018-07-19"
        sample = "037df38bd30a08ac4f8bff53a33070b8"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 512000 and
        hash.md5(0,filesize) ==  "037df38bd30a08ac4f8bff53a33070b8"
}        
        
rule r3e3668b0419a5dabaa55b073a3bf4ec5 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.86 32bit (2018-05-28 10:07:38)"
        author = "@viql"
        date = "2018-07-19"
        sample = "3e3668b0419a5dabaa55b073a3bf4ec5"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 516096 and
        hash.md5(0,filesize) ==  "3e3668b0419a5dabaa55b073a3bf4ec5"
}        
        
rule r454f07d141e4139baeeba5bb75701bfc {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.87 64bit (2018-06-11 12:25:18)"
        author = "@viql"
        date = "2018-07-19"
        sample = "454f07d141e4139baeeba5bb75701bfc"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 626688 and
        hash.md5(0,filesize) ==  "454f07d141e4139baeeba5bb75701bfc"
}        
        
rule r3faa10d75f57d08e4945bcfed2cc036d {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.85 64bit (2018-04-27 15:22:59)"
        author = "@viql"
        date = "2018-07-19"
        sample = "3faa10d75f57d08e4945bcfed2cc036d"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "3faa10d75f57d08e4945bcfed2cc036d"
}        
        
rule rd8c6f5d7d60a8c10fe1773c50d426079 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.66 64bit (2017-09-18 05:13:14)"
        author = "@viql"
        date = "2018-07-19"
        sample = "d8c6f5d7d60a8c10fe1773c50d426079"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 466944 and
        hash.md5(0,filesize) ==  "d8c6f5d7d60a8c10fe1773c50d426079"
}        
        
rule r996c8c52b5aa9626cbbff991d86ced57 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.68 64bit (2017-10-24 05:15:49)"
        author = "@viql"
        date = "2018-07-19"
        sample = "996c8c52b5aa9626cbbff991d86ced57"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 446464 and
        hash.md5(0,filesize) ==  "996c8c52b5aa9626cbbff991d86ced57"
}        
        
rule r063ef17c48eae1c326e6cd97364e5f9f {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.80 32bit (2017-12-16 13:22:48)"
        author = "@viql"
        date = "2018-07-19"
        sample = "063ef17c48eae1c326e6cd97364e5f9f"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 352256 and
        hash.md5(0,filesize) ==  "063ef17c48eae1c326e6cd97364e5f9f"
}        
        
rule r66034294e67c0465453fc080b22ae76a {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.83 32bit (2018-02-16 07:10:44)"
        author = "@viql"
        date = "2018-07-19"
        sample = "66034294e67c0465453fc080b22ae76a"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 491520 and
        hash.md5(0,filesize) ==  "66034294e67c0465453fc080b22ae76a"
}        
        
rule r1677932806f6cad5af01fa3a58bed742 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.82 32bit (2018-02-05 08:48:30)"
        author = "@viql"
        date = "2018-07-19"
        sample = "1677932806f6cad5af01fa3a58bed742"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 487424 and
        hash.md5(0,filesize) ==  "1677932806f6cad5af01fa3a58bed742"
}        
        
rule rb8beaa92ef68417b6f71306335529b3e {
    meta:
        description = "Dridex module: Botnet 7200, module 'bot' 32bit (2018-07-17 05:25:16)"
        author = "@viql"
        date = "2018-07-19"
        sample = "b8beaa92ef68417b6f71306335529b3e"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 536576 and
        hash.md5(0,filesize) ==  "b8beaa92ef68417b6f71306335529b3e"
}        
        
rule r3a0d92cfbf66a1c2d7b8af22c6008d19 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' 64bit (2018-06-11 12:25:18)"
        author = "@viql"
        date = "2018-07-19"
        sample = "3a0d92cfbf66a1c2d7b8af22c6008d19"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 626688 and
        hash.md5(0,filesize) ==  "3a0d92cfbf66a1c2d7b8af22c6008d19"
}        
        
rule rdedc619260039024df1dda42b2fbf01b {
    meta:
        description = "Dridex module: Botnet 7200, module 'bot' 64bit (2018-06-25 14:19:46)"
        author = "@viql"
        date = "2018-07-19"
        sample = "dedc619260039024df1dda42b2fbf01b"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 634880 and
        hash.md5(0,filesize) ==  "dedc619260039024df1dda42b2fbf01b"
}        
        
rule rcffb11367fa1833d4b8fd74fc3b48f06 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.80 64bit (2017-12-16 13:23:00)"
        author = "@viql"
        date = "2018-07-19"
        sample = "cffb11367fa1833d4b8fd74fc3b48f06"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 471040 and
        hash.md5(0,filesize) ==  "cffb11367fa1833d4b8fd74fc3b48f06"
}        
        
rule r5c0904e7ede84040e3b1f172e4892c31 {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' version 4.85 32bit (2018-05-01 14:42:31)"
        author = "@viql"
        date = "2018-07-19"
        sample = "5c0904e7ede84040e3b1f172e4892c31"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 503808 and
        hash.md5(0,filesize) ==  "5c0904e7ede84040e3b1f172e4892c31"
}        
        
rule r7288dcfd23281720d7ce80925db59abe {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.14 32bit (2018-06-21 09:42:24)"
        author = "@viql"
        date = "2018-07-19"
        sample = "7288dcfd23281720d7ce80925db59abe"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 512000 and
        hash.md5(0,filesize) ==  "7288dcfd23281720d7ce80925db59abe"
}        
        
rule r8cfa2bc7ce6cc76fb7252392d29e9a21 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.66 32bit (2017-09-18 05:13:00)"
        author = "@viql"
        date = "2018-07-19"
        sample = "8cfa2bc7ce6cc76fb7252392d29e9a21"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 348160 and
        hash.md5(0,filesize) ==  "8cfa2bc7ce6cc76fb7252392d29e9a21"
}        
        
rule rd7854efc87ca10aed77e77ada1015b64 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.86 32bit (2018-05-31 12:08:00)"
        author = "@viql"
        date = "2018-07-19"
        sample = "d7854efc87ca10aed77e77ada1015b64"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 507904 and
        hash.md5(0,filesize) ==  "d7854efc87ca10aed77e77ada1015b64"
}        
        
rule rd819d6785b313258f4434b5e3db7b268 {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.85 32bit (2018-03-23 18:13:27)"
        author = "@viql"
        date = "2018-07-19"
        sample = "d819d6785b313258f4434b5e3db7b268"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "d819d6785b313258f4434b5e3db7b268"
}        
        
rule rd00d71561128c16770349bc0241c9de4 {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' version 4.14 64bit (2018-06-21 09:42:38)"
        author = "@viql"
        date = "2018-07-19"
        sample = "d00d71561128c16770349bc0241c9de4"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 626688 and
        hash.md5(0,filesize) ==  "d00d71561128c16770349bc0241c9de4"
}        
        
rule r853da33cc33197c15718ffb9220fbcaf {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.14 64bit (2018-06-12 13:00:06)"
        author = "@viql"
        date = "2018-07-19"
        sample = "853da33cc33197c15718ffb9220fbcaf"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 638976 and
        hash.md5(0,filesize) ==  "853da33cc33197c15718ffb9220fbcaf"
}        
        
rule r3eade9e5b3dbdfdd2bd16571be498fd3 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.85 32bit (2018-03-20 09:33:41)"
        author = "@viql"
        date = "2018-07-19"
        sample = "3eade9e5b3dbdfdd2bd16571be498fd3"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 487424 and
        hash.md5(0,filesize) ==  "3eade9e5b3dbdfdd2bd16571be498fd3"
}        
        
rule rcafec8ab7a6d2cffd2afdf3220a5550b {
    meta:
        description = "Dridex module: Botnet 10105, module 'bot' 64bit (2018-06-21 09:42:38)"
        author = "@viql"
        date = "2018-07-19"
        sample = "cafec8ab7a6d2cffd2afdf3220a5550b"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 626688 and
        hash.md5(0,filesize) ==  "cafec8ab7a6d2cffd2afdf3220a5550b"
}        
        
rule r271543a2e8ecb8d5fe9abf73441a982e {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.85 64bit (2018-03-14 21:36:57)"
        author = "@viql"
        date = "2018-07-19"
        sample = "271543a2e8ecb8d5fe9abf73441a982e"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "271543a2e8ecb8d5fe9abf73441a982e"
}        
        
rule r879d3069145d6276f2a1cb8135f4078a {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.85 32bit (2018-03-14 21:36:42)"
        author = "@viql"
        date = "2018-07-19"
        sample = "879d3069145d6276f2a1cb8135f4078a"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "879d3069145d6276f2a1cb8135f4078a"
}        
        
rule r16ddc8752e5724eff475e6c558b5c269 {
    meta:
        description = "Dridex module: Botnet 10105, module 'bot' version 4.14 32bit (2018-06-09 21:34:24)"
        author = "@viql"
        date = "2018-07-19"
        sample = "16ddc8752e5724eff475e6c558b5c269"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 577536 and
        hash.md5(0,filesize) ==  "16ddc8752e5724eff475e6c558b5c269"
}        
        
rule rbb733999c6e083528901dc29bdc966e8 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.86 32bit (2018-06-06 12:00:17)"
        author = "@viql"
        date = "2018-07-19"
        sample = "bb733999c6e083528901dc29bdc966e8"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 536576 and
        hash.md5(0,filesize) ==  "bb733999c6e083528901dc29bdc966e8"
}        
        
rule r4671d287f4d5f0cafbd00de50ef25510 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.87 32bit (2018-06-21 09:42:24)"
        author = "@viql"
        date = "2018-07-19"
        sample = "4671d287f4d5f0cafbd00de50ef25510"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 512000 and
        hash.md5(0,filesize) ==  "4671d287f4d5f0cafbd00de50ef25510"
}        
        
rule r1af43327df1853278496baa53190380b {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.59 32bit (2017-06-26 06:04:50)"
        author = "@viql"
        date = "2018-07-19"
        sample = "1af43327df1853278496baa53190380b"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 335872 and
        hash.md5(0,filesize) ==  "1af43327df1853278496baa53190380b"
}        
        
rule ra5baa566a3e9675d304e56e3cf512916 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.87 64bit (2018-06-21 09:42:38)"
        author = "@viql"
        date = "2018-07-19"
        sample = "a5baa566a3e9675d304e56e3cf512916"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 626688 and
        hash.md5(0,filesize) ==  "a5baa566a3e9675d304e56e3cf512916"
}        
        
rule rf5d5af53b99ecfcc1696e943ec95a6c3 {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' version 4.86 64bit (2018-06-01 18:49:48)"
        author = "@viql"
        date = "2018-07-19"
        sample = "f5d5af53b99ecfcc1696e943ec95a6c3"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 638976 and
        hash.md5(0,filesize) ==  "f5d5af53b99ecfcc1696e943ec95a6c3"
}        
        
rule rb91c009b7c2df0c98ed679e6076aead7 {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' version 4.14 64bit (2018-06-12 13:00:06)"
        author = "@viql"
        date = "2018-07-19"
        sample = "b91c009b7c2df0c98ed679e6076aead7"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 638976 and
        hash.md5(0,filesize) ==  "b91c009b7c2df0c98ed679e6076aead7"
}        
        
rule r123ca5b9d0858aa5e67c79f483ec1cea {
    meta:
        description = "Dridex module: Botnet 7200, module 'bot' version 4.85 64bit (2018-03-11 07:22:01)"
        author = "@viql"
        date = "2018-07-19"
        sample = "123ca5b9d0858aa5e67c79f483ec1cea"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "123ca5b9d0858aa5e67c79f483ec1cea"
}        
        
rule r507596b2d517678183717c4e682be03d {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' version 4.85 64bit (2018-04-27 15:22:59)"
        author = "@viql"
        date = "2018-07-19"
        sample = "507596b2d517678183717c4e682be03d"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "507596b2d517678183717c4e682be03d"
}        
        
rule r1048b874e0896a0c3d298f431769668c {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.85 32bit (2018-04-27 15:22:32)"
        author = "@viql"
        date = "2018-07-19"
        sample = "1048b874e0896a0c3d298f431769668c"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 548864 and
        hash.md5(0,filesize) ==  "1048b874e0896a0c3d298f431769668c"
}        
        
rule r81135fa4b14a33cdbda15ebc1ec58294 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.68 64bit (2017-10-30 07:04:49)"
        author = "@viql"
        date = "2018-07-19"
        sample = "81135fa4b14a33cdbda15ebc1ec58294"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 442368 and
        hash.md5(0,filesize) ==  "81135fa4b14a33cdbda15ebc1ec58294"
}        
        
rule ra65c1290917373b6ebb0543df9ca21a2 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.86 64bit (2018-06-01 18:49:48)"
        author = "@viql"
        date = "2018-07-19"
        sample = "a65c1290917373b6ebb0543df9ca21a2"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 638976 and
        hash.md5(0,filesize) ==  "a65c1290917373b6ebb0543df9ca21a2"
}        
        
rule rb3c512ffa0ec2906500c70140b38a27b {
    meta:
        description = "Dridex module: Botnet 10105, module 'bot' version 4.14 64bit (2018-06-09 21:34:34)"
        author = "@viql"
        date = "2018-07-19"
        sample = "b3c512ffa0ec2906500c70140b38a27b"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 716800 and
        hash.md5(0,filesize) ==  "b3c512ffa0ec2906500c70140b38a27b"
}        
        
rule r964e6212ab22e166a343f5417514f62d {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.83 32bit (2018-02-16 07:12:54)"
        author = "@viql"
        date = "2018-07-19"
        sample = "964e6212ab22e166a343f5417514f62d"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 491520 and
        hash.md5(0,filesize) ==  "964e6212ab22e166a343f5417514f62d"
}        
        
rule r94fd7c297e7ddc4dc2ba51af095685d0 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.82 32bit (2018-02-05 09:27:42)"
        author = "@viql"
        date = "2018-07-19"
        sample = "94fd7c297e7ddc4dc2ba51af095685d0"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "94fd7c297e7ddc4dc2ba51af095685d0"
}        
        
rule re6fc8ac7c3844e1a040e5fae6e47de7c {
    meta:
        description = "Dridex module: Botnet 7200, module 'bot' version 4.14 32bit (2018-06-07 14:14:34)"
        author = "@viql"
        date = "2018-07-19"
        sample = "e6fc8ac7c3844e1a040e5fae6e47de7c"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 532480 and
        hash.md5(0,filesize) ==  "e6fc8ac7c3844e1a040e5fae6e47de7c"
}        
        
rule rd909405643ee63f045b9a38695564536 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.85 64bit (2018-04-27 15:22:59)"
        author = "@viql"
        date = "2018-07-19"
        sample = "d909405643ee63f045b9a38695564536"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "d909405643ee63f045b9a38695564536"
}        
        
rule ra4aad924d78d7070831ec5695f19dc78 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.85 32bit (2018-03-14 21:36:42)"
        author = "@viql"
        date = "2018-07-19"
        sample = "a4aad924d78d7070831ec5695f19dc78"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "a4aad924d78d7070831ec5695f19dc78"
}        
        
rule r876fa2bab0a90e8d84045f71bb84f734 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.85 32bit (2018-02-20 13:02:28)"
        author = "@viql"
        date = "2018-07-19"
        sample = "876fa2bab0a90e8d84045f71bb84f734"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 491520 and
        hash.md5(0,filesize) ==  "876fa2bab0a90e8d84045f71bb84f734"
}        
        
rule r20cb606139fa6f13b87b32997dc5aa95 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.62 64bit (2017-08-12 22:22:06)"
        author = "@viql"
        date = "2018-07-19"
        sample = "20cb606139fa6f13b87b32997dc5aa95"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 454656 and
        hash.md5(0,filesize) ==  "20cb606139fa6f13b87b32997dc5aa95"
}        
        
rule r58692ccca8e32b7c7f48e76be001bfa0 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.67 32bit (2017-10-02 22:19:39)"
        author = "@viql"
        date = "2018-07-19"
        sample = "58692ccca8e32b7c7f48e76be001bfa0"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 331776 and
        hash.md5(0,filesize) ==  "58692ccca8e32b7c7f48e76be001bfa0"
}        
        
rule r6d3b2c5ee970e7c37d24dce9d9f70666 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.85 64bit (2018-02-27 09:23:53)"
        author = "@viql"
        date = "2018-07-19"
        sample = "6d3b2c5ee970e7c37d24dce9d9f70666"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 696320 and
        hash.md5(0,filesize) ==  "6d3b2c5ee970e7c37d24dce9d9f70666"
}        
        
rule r033d7486b43935a8adf5796835d088d4 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.85 64bit (2018-03-23 18:14:53)"
        author = "@viql"
        date = "2018-07-19"
        sample = "033d7486b43935a8adf5796835d088d4"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "033d7486b43935a8adf5796835d088d4"
}        
        
rule r11b78e9ee07ec42a671695487e802e0e {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' version 4.86 32bit (2018-05-31 12:30:21)"
        author = "@viql"
        date = "2018-07-19"
        sample = "11b78e9ee07ec42a671695487e802e0e"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 507904 and
        hash.md5(0,filesize) ==  "11b78e9ee07ec42a671695487e802e0e"
}        
        
rule rba191e35a260f6d106ccbe82a10aa5cc {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.73 32bit (2017-11-16 15:02:24)"
        author = "@viql"
        date = "2018-07-19"
        sample = "ba191e35a260f6d106ccbe82a10aa5cc"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 352256 and
        hash.md5(0,filesize) ==  "ba191e35a260f6d106ccbe82a10aa5cc"
}        
        
rule rd957cda6190e8e04e7ed6d3cb8f79326 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.67 64bit (2017-10-12 23:32:10)"
        author = "@viql"
        date = "2018-07-19"
        sample = "d957cda6190e8e04e7ed6d3cb8f79326"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 466944 and
        hash.md5(0,filesize) ==  "d957cda6190e8e04e7ed6d3cb8f79326"
}        
        
rule rbd99593799165161126d17cabd164460 {
    meta:
        description = "Dridex module: Botnet 7200, module 'bot' 64bit (2018-07-17 05:25:28)"
        author = "@viql"
        date = "2018-07-19"
        sample = "bd99593799165161126d17cabd164460"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "bd99593799165161126d17cabd164460"
}        
        
rule rf441b8d2f70ef84e8cc71556f293ff7a {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.80 64bit (2017-12-22 22:29:34)"
        author = "@viql"
        date = "2018-07-19"
        sample = "f441b8d2f70ef84e8cc71556f293ff7a"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 471040 and
        hash.md5(0,filesize) ==  "f441b8d2f70ef84e8cc71556f293ff7a"
}        
        
rule rdf80d463f19b61f2bc10622e2172fd36 {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.85 64bit (2018-03-11 07:48:28)"
        author = "@viql"
        date = "2018-07-19"
        sample = "df80d463f19b61f2bc10622e2172fd36"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "df80d463f19b61f2bc10622e2172fd36"
}        
        
rule r85d3adf228524bb7bc6ea66d12ef18cd {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.85 32bit (2018-03-06 10:05:22)"
        author = "@viql"
        date = "2018-07-19"
        sample = "85d3adf228524bb7bc6ea66d12ef18cd"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "85d3adf228524bb7bc6ea66d12ef18cd"
}        
        
rule rd053911bbc6865377eb70720aa4c4d4d {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.83 64bit (2018-02-16 07:13:10)"
        author = "@viql"
        date = "2018-07-19"
        sample = "d053911bbc6865377eb70720aa4c4d4d"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 684032 and
        hash.md5(0,filesize) ==  "d053911bbc6865377eb70720aa4c4d4d"
}        
        
rule ra8d7b2014fa44252967635c15f8cab50 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.85 64bit (2018-03-20 09:35:23)"
        author = "@viql"
        date = "2018-07-19"
        sample = "a8d7b2014fa44252967635c15f8cab50"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 643072 and
        hash.md5(0,filesize) ==  "a8d7b2014fa44252967635c15f8cab50"
}        
        
rule r3f7155b3a742fdf5d8539ec384090510 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.82 64bit (2018-02-05 08:48:40)"
        author = "@viql"
        date = "2018-07-19"
        sample = "3f7155b3a742fdf5d8539ec384090510"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 753664 and
        hash.md5(0,filesize) ==  "3f7155b3a742fdf5d8539ec384090510"
}        
        
rule r353053924fb970d00e3ad897eeaa1ff5 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.85 32bit (2018-02-19 06:53:37)"
        author = "@viql"
        date = "2018-07-19"
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
        description = "Dridex module: Botnet 2144, module 'bot' version 4.83 32bit (2018-02-16 07:07:06)"
        author = "@viql"
        date = "2018-07-19"
        sample = "7c7d957fcd93ef3d1b78054aa2fb4472"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 491520 and
        hash.md5(0,filesize) ==  "7c7d957fcd93ef3d1b78054aa2fb4472"
}        
        
rule r7ee2fbfee2623de1bc5b7ae3a0633891 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.85 64bit (2018-03-14 21:36:57)"
        author = "@viql"
        date = "2018-07-19"
        sample = "7ee2fbfee2623de1bc5b7ae3a0633891"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "7ee2fbfee2623de1bc5b7ae3a0633891"
}        
        
rule rceeb0c36d1eeb5f35f82ddd3bce58716 {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.85 64bit (2018-03-23 18:13:54)"
        author = "@viql"
        date = "2018-07-19"
        sample = "ceeb0c36d1eeb5f35f82ddd3bce58716"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "ceeb0c36d1eeb5f35f82ddd3bce58716"
}        
        
rule rb5a7401a29ca860ed128f9f1ad4aaecd {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.86 64bit (2018-05-28 10:07:56)"
        author = "@viql"
        date = "2018-07-19"
        sample = "b5a7401a29ca860ed128f9f1ad4aaecd"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 659456 and
        hash.md5(0,filesize) ==  "b5a7401a29ca860ed128f9f1ad4aaecd"
}        
        
rule r2967e39fe0b22f020489028f159c620b {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.80 64bit (2018-01-09 20:01:21)"
        author = "@viql"
        date = "2018-07-19"
        sample = "2967e39fe0b22f020489028f159c620b"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 712704 and
        hash.md5(0,filesize) ==  "2967e39fe0b22f020489028f159c620b"
}        
        
rule rb23a9bd3ee31af8b78d18bb92e7f2257 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.85 64bit (2018-02-19 06:53:59)"
        author = "@viql"
        date = "2018-07-19"
        sample = "b23a9bd3ee31af8b78d18bb92e7f2257"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 675840 and
        hash.md5(0,filesize) ==  "b23a9bd3ee31af8b78d18bb92e7f2257"
}        
        
rule rf93155d82bdbdd513f93106240b35b17 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.75 32bit (2017-12-04 07:37:40)"
        author = "@viql"
        date = "2018-07-19"
        sample = "f93155d82bdbdd513f93106240b35b17"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 352256 and
        hash.md5(0,filesize) ==  "f93155d82bdbdd513f93106240b35b17"
}        
        
rule r8319f4b39bd607041bc71e6b748fb533 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.65 64bit (2017-09-04 18:29:51)"
        author = "@viql"
        date = "2018-07-19"
        sample = "8319f4b39bd607041bc71e6b748fb533"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 471040 and
        hash.md5(0,filesize) ==  "8319f4b39bd607041bc71e6b748fb533"
}        
        
rule ra11c136cdc4d8a9123759980bf7aa3bb {
    meta:
        description = "Dridex module: Botnet 7200, module 'bot' version 4.87 32bit (2018-06-11 12:24:30)"
        author = "@viql"
        date = "2018-07-19"
        sample = "a11c136cdc4d8a9123759980bf7aa3bb"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 512000 and
        hash.md5(0,filesize) ==  "a11c136cdc4d8a9123759980bf7aa3bb"
}        
        
rule re755a16547585be1e7338762828c88f0 {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.85 32bit (2018-03-20 09:33:41)"
        author = "@viql"
        date = "2018-07-19"
        sample = "e755a16547585be1e7338762828c88f0"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 487424 and
        hash.md5(0,filesize) ==  "e755a16547585be1e7338762828c88f0"
}        
        
rule rf05fa10b6502a04357bd1db4fc59cd1e {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' 32bit (2018-06-21 09:42:24)"
        author = "@viql"
        date = "2018-07-19"
        sample = "f05fa10b6502a04357bd1db4fc59cd1e"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 512000 and
        hash.md5(0,filesize) ==  "f05fa10b6502a04357bd1db4fc59cd1e"
}        
        
rule r8714e50aee6ed1c8a9dccc418066e0a3 {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' version 4.14 32bit (2018-06-21 09:42:24)"
        author = "@viql"
        date = "2018-07-19"
        sample = "8714e50aee6ed1c8a9dccc418066e0a3"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 512000 and
        hash.md5(0,filesize) ==  "8714e50aee6ed1c8a9dccc418066e0a3"
}        
        
rule r50362d3a3b3d25985c6682cdc07dc656 {
    meta:
        description = "Dridex module: Botnet 10105, module 'bot' version 2.25 64bit (2018-06-20 13:14:44)"
        author = "@viql"
        date = "2018-07-19"
        sample = "50362d3a3b3d25985c6682cdc07dc656"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 704512 and
        hash.md5(0,filesize) ==  "50362d3a3b3d25985c6682cdc07dc656"
}        
        
rule rad343e1aa8fb15c5cf04dd817fd3a1dd {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.68 32bit (2017-10-30 07:04:31)"
        author = "@viql"
        date = "2018-07-19"
        sample = "ad343e1aa8fb15c5cf04dd817fd3a1dd"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 360448 and
        hash.md5(0,filesize) ==  "ad343e1aa8fb15c5cf04dd817fd3a1dd"
}        
        
rule r9a21726fdd1054098d4e75c84fde5b7f {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' 64bit (2018-06-21 09:42:38)"
        author = "@viql"
        date = "2018-07-19"
        sample = "9a21726fdd1054098d4e75c84fde5b7f"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 626688 and
        hash.md5(0,filesize) ==  "9a21726fdd1054098d4e75c84fde5b7f"
}        
        
rule rde6425b9b266455b8009129085f99117 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.85 32bit (2018-03-23 18:14:41)"
        author = "@viql"
        date = "2018-07-19"
        sample = "de6425b9b266455b8009129085f99117"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "de6425b9b266455b8009129085f99117"
}        
        
rule r4e29341b39d1f32e50546a8ac2ac8871 {
    meta:
        description = "Dridex module: Botnet 7200, module 'bot' version 4.85 32bit (2018-03-11 07:21:42)"
        author = "@viql"
        date = "2018-07-19"
        sample = "4e29341b39d1f32e50546a8ac2ac8871"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "4e29341b39d1f32e50546a8ac2ac8871"
}        
        
rule rd25709b54bb78ed8e34652bf23072dae {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.74 32bit (2017-11-21 13:51:49)"
        author = "@viql"
        date = "2018-07-19"
        sample = "d25709b54bb78ed8e34652bf23072dae"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 348160 and
        hash.md5(0,filesize) ==  "d25709b54bb78ed8e34652bf23072dae"
}        
        
rule r2f5373c1244bb6d50f70952b93f3ae03 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.86 32bit (2018-06-06 12:00:17)"
        author = "@viql"
        date = "2018-07-19"
        sample = "2f5373c1244bb6d50f70952b93f3ae03"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 536576 and
        hash.md5(0,filesize) ==  "2f5373c1244bb6d50f70952b93f3ae03"
}        
        
rule r0f676b95ae81e27ae286194fc2c90fb6 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.61 32bit (2017-07-25 16:30:40)"
        author = "@viql"
        date = "2018-07-19"
        sample = "0f676b95ae81e27ae286194fc2c90fb6"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 331776 and
        hash.md5(0,filesize) ==  "0f676b95ae81e27ae286194fc2c90fb6"
}        
        
rule r67290af5a4d60537720e54a4fc6b4d97 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.62 64bit (2017-08-03 20:33:08)"
        author = "@viql"
        date = "2018-07-19"
        sample = "67290af5a4d60537720e54a4fc6b4d97"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 466944 and
        hash.md5(0,filesize) ==  "67290af5a4d60537720e54a4fc6b4d97"
}        
        
rule r4faf563dad4c18854c416562fe6cf6a1 {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' version 4.86 64bit (2018-05-29 11:40:10)"
        author = "@viql"
        date = "2018-07-19"
        sample = "4faf563dad4c18854c416562fe6cf6a1"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 659456 and
        hash.md5(0,filesize) ==  "4faf563dad4c18854c416562fe6cf6a1"
}        
        
rule rd976b6794dfb4ce442319269a642bba4 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.86 64bit (2018-06-06 10:58:14)"
        author = "@viql"
        date = "2018-07-19"
        sample = "d976b6794dfb4ce442319269a642bba4"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 638976 and
        hash.md5(0,filesize) ==  "d976b6794dfb4ce442319269a642bba4"
}        
        
rule r6b68cb8768d8c6a0badcd1bbdafb8af7 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.85 32bit (2018-03-06 22:04:31)"
        author = "@viql"
        date = "2018-07-19"
        sample = "6b68cb8768d8c6a0badcd1bbdafb8af7"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 487424 and
        hash.md5(0,filesize) ==  "6b68cb8768d8c6a0badcd1bbdafb8af7"
}        
        
rule r1fbbcd16d07fa55c40db393e0916dd1c {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.61 64bit (2017-07-25 16:27:55)"
        author = "@viql"
        date = "2018-07-19"
        sample = "1fbbcd16d07fa55c40db393e0916dd1c"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 450560 and
        hash.md5(0,filesize) ==  "1fbbcd16d07fa55c40db393e0916dd1c"
}        
        
rule r0adecaad257848c99178f364695562cf {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' 32bit (2018-06-15 09:01:06)"
        author = "@viql"
        date = "2018-07-19"
        sample = "0adecaad257848c99178f364695562cf"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 507904 and
        hash.md5(0,filesize) ==  "0adecaad257848c99178f364695562cf"
}        
        
rule r9f138ef68f86abadf9f78602083f79bb {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.86 64bit (2018-05-29 10:20:33)"
        author = "@viql"
        date = "2018-07-19"
        sample = "9f138ef68f86abadf9f78602083f79bb"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 659456 and
        hash.md5(0,filesize) ==  "9f138ef68f86abadf9f78602083f79bb"
}        
        
rule r30b4f2c39803220f1712529c07186924 {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' 32bit (2018-05-30 15:10:38)"
        author = "@viql"
        date = "2018-07-19"
        sample = "30b4f2c39803220f1712529c07186924"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 528384 and
        hash.md5(0,filesize) ==  "30b4f2c39803220f1712529c07186924"
}        
        
rule r1f97c1a405ceec89de6a05c8fc44a356 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.87 32bit (2018-06-11 12:24:30)"
        author = "@viql"
        date = "2018-07-19"
        sample = "1f97c1a405ceec89de6a05c8fc44a356"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 512000 and
        hash.md5(0,filesize) ==  "1f97c1a405ceec89de6a05c8fc44a356"
}        
        
rule r7ca54a11bf979832c19000d53874bb23 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.85 64bit (2018-02-20 13:02:42)"
        author = "@viql"
        date = "2018-07-19"
        sample = "7ca54a11bf979832c19000d53874bb23"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 675840 and
        hash.md5(0,filesize) ==  "7ca54a11bf979832c19000d53874bb23"
}        
        
rule rd0436a7e50f39e42f00eee73a9ba7be6 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.65 64bit (2017-08-27 11:14:58)"
        author = "@viql"
        date = "2018-07-19"
        sample = "d0436a7e50f39e42f00eee73a9ba7be6"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 446464 and
        hash.md5(0,filesize) ==  "d0436a7e50f39e42f00eee73a9ba7be6"
}        
        
rule re0b43753cf06c3ccd65c9e5b54fb74ee {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.80 32bit (2018-01-09 20:01:07)"
        author = "@viql"
        date = "2018-07-19"
        sample = "e0b43753cf06c3ccd65c9e5b54fb74ee"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 487424 and
        hash.md5(0,filesize) ==  "e0b43753cf06c3ccd65c9e5b54fb74ee"
}        
        
rule r2415a6f409c9572f7eda4ba789359c56 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.74 64bit (2017-11-25 13:14:49)"
        author = "@viql"
        date = "2018-07-19"
        sample = "2415a6f409c9572f7eda4ba789359c56"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "2415a6f409c9572f7eda4ba789359c56"
}        
        
rule r9cff4061c873bc9bc8db8778333c094b {
    meta:
        description = "Dridex module: Botnet 10105, module 'bot' version 2.25 32bit (2018-06-20 13:14:34)"
        author = "@viql"
        date = "2018-07-19"
        sample = "9cff4061c873bc9bc8db8778333c094b"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 573440 and
        hash.md5(0,filesize) ==  "9cff4061c873bc9bc8db8778333c094b"
}        
        
rule rdcea2c788ca7600c1a5a9fe340f42869 {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' version 4.86 64bit (2018-05-31 12:30:36)"
        author = "@viql"
        date = "2018-07-19"
        sample = "dcea2c788ca7600c1a5a9fe340f42869"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 643072 and
        hash.md5(0,filesize) ==  "dcea2c788ca7600c1a5a9fe340f42869"
}        
        
rule r306b584f2b6189699b9597a14734fa95 {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.85 32bit (2018-03-11 07:48:14)"
        author = "@viql"
        date = "2018-07-19"
        sample = "306b584f2b6189699b9597a14734fa95"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "306b584f2b6189699b9597a14734fa95"
}        
        
rule r745bd761aaaaa56879f57d5e0cdeae9c {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' version 4.86 32bit (2018-06-06 12:00:17)"
        author = "@viql"
        date = "2018-07-19"
        sample = "745bd761aaaaa56879f57d5e0cdeae9c"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 536576 and
        hash.md5(0,filesize) ==  "745bd761aaaaa56879f57d5e0cdeae9c"
}        
        
rule re12b7bbb65aa0b1c1d63c3ebd59ad115 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.85 64bit (2018-03-11 07:22:01)"
        author = "@viql"
        date = "2018-07-19"
        sample = "e12b7bbb65aa0b1c1d63c3ebd59ad115"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "e12b7bbb65aa0b1c1d63c3ebd59ad115"
}        
        
rule rba6d916e590e037596aef06bf09d5796 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.86 64bit (2018-05-30 12:17:53)"
        author = "@viql"
        date = "2018-07-19"
        sample = "ba6d916e590e037596aef06bf09d5796"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 659456 and
        hash.md5(0,filesize) ==  "ba6d916e590e037596aef06bf09d5796"
}        
        
rule rb773caf389f2da2e4aeadc1f9fd69b2a {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.85 32bit (2018-03-11 07:21:42)"
        author = "@viql"
        date = "2018-07-19"
        sample = "b773caf389f2da2e4aeadc1f9fd69b2a"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "b773caf389f2da2e4aeadc1f9fd69b2a"
}        
        
rule r32b2e94cb2f7d4a71123b4f9585c63b3 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.85 32bit (2018-02-27 09:23:39)"
        author = "@viql"
        date = "2018-07-19"
        sample = "32b2e94cb2f7d4a71123b4f9585c63b3"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "32b2e94cb2f7d4a71123b4f9585c63b3"
}        
        
rule rbf91a9159929614de2f9dc95c59de516 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.67 32bit (2017-10-12 23:31:56)"
        author = "@viql"
        date = "2018-07-19"
        sample = "bf91a9159929614de2f9dc95c59de516"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 348160 and
        hash.md5(0,filesize) ==  "bf91a9159929614de2f9dc95c59de516"
}        
        
rule r4796d47eb1ae2c03c98d31c4bb9e7327 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.83 64bit (2018-02-16 07:10:56)"
        author = "@viql"
        date = "2018-07-19"
        sample = "4796d47eb1ae2c03c98d31c4bb9e7327"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 684032 and
        hash.md5(0,filesize) ==  "4796d47eb1ae2c03c98d31c4bb9e7327"
}        
        
rule r8d26bc42ba1906fefe4c4f63c4b0802e {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.85 64bit (2018-03-11 07:45:56)"
        author = "@viql"
        date = "2018-07-19"
        sample = "8d26bc42ba1906fefe4c4f63c4b0802e"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "8d26bc42ba1906fefe4c4f63c4b0802e"
}        
        
rule r2a02912728b77f6a5cc57812dac7be62 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.68 32bit (2017-10-18 11:33:35)"
        author = "@viql"
        date = "2018-07-19"
        sample = "2a02912728b77f6a5cc57812dac7be62"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 352256 and
        hash.md5(0,filesize) ==  "2a02912728b77f6a5cc57812dac7be62"
}        
        
rule r8deb67a267969ce49f87cc3623849507 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.65 32bit (2017-09-04 18:28:42)"
        author = "@viql"
        date = "2018-07-19"
        sample = "8deb67a267969ce49f87cc3623849507"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 352256 and
        hash.md5(0,filesize) ==  "8deb67a267969ce49f87cc3623849507"
}        
        
rule r1264dbcf9106b7adab3682b9b42bdfcf {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.80 64bit (2018-01-18 13:04:13)"
        author = "@viql"
        date = "2018-07-19"
        sample = "1264dbcf9106b7adab3682b9b42bdfcf"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 757760 and
        hash.md5(0,filesize) ==  "1264dbcf9106b7adab3682b9b42bdfcf"
}        
        
rule rfd76f3edc765e6c5971eab6c070b0963 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.86 64bit (2018-06-06 12:00:27)"
        author = "@viql"
        date = "2018-07-19"
        sample = "fd76f3edc765e6c5971eab6c070b0963"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 638976 and
        hash.md5(0,filesize) ==  "fd76f3edc765e6c5971eab6c070b0963"
}        
        
rule rf71ea8289672e4358fff0c5113b97b81 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.85 32bit (2018-05-01 14:42:31)"
        author = "@viql"
        date = "2018-07-19"
        sample = "f71ea8289672e4358fff0c5113b97b81"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 503808 and
        hash.md5(0,filesize) ==  "f71ea8289672e4358fff0c5113b97b81"
}        
        
rule r011687661ecc9673141e8ffafb7004af {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.82 64bit (2018-02-05 09:28:13)"
        author = "@viql"
        date = "2018-07-19"
        sample = "011687661ecc9673141e8ffafb7004af"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 753664 and
        hash.md5(0,filesize) ==  "011687661ecc9673141e8ffafb7004af"
}        
        
rule rc90e9696aa3240f154b91f70a574d26e {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.86 64bit (2018-06-01 18:28:42)"
        author = "@viql"
        date = "2018-07-19"
        sample = "c90e9696aa3240f154b91f70a574d26e"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 638976 and
        hash.md5(0,filesize) ==  "c90e9696aa3240f154b91f70a574d26e"
}        
        
rule r56152d48f52c337e2348c75254f142db {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.62 32bit (2017-08-20 16:03:41)"
        author = "@viql"
        date = "2018-07-19"
        sample = "56152d48f52c337e2348c75254f142db"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 331776 and
        hash.md5(0,filesize) ==  "56152d48f52c337e2348c75254f142db"
}        
        
rule rec58af9975f6322fbe54ef8861c4ab25 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.71 64bit (2017-11-08 12:31:23)"
        author = "@viql"
        date = "2018-07-19"
        sample = "ec58af9975f6322fbe54ef8861c4ab25"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 466944 and
        hash.md5(0,filesize) ==  "ec58af9975f6322fbe54ef8861c4ab25"
}        
        
rule r21d41ea27f6ae652760967cb81a9216c {
    meta:
        description = "Dridex module: Botnet 7200, module 'bot' 32bit (2018-07-16 09:22:08)"
        author = "@viql"
        date = "2018-07-19"
        sample = "21d41ea27f6ae652760967cb81a9216c"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 536576 and
        hash.md5(0,filesize) ==  "21d41ea27f6ae652760967cb81a9216c"
}        
        
rule r93bfdb5b9810387f1769a6f76461f550 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.85 32bit (2018-03-11 07:21:42)"
        author = "@viql"
        date = "2018-07-19"
        sample = "93bfdb5b9810387f1769a6f76461f550"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "93bfdb5b9810387f1769a6f76461f550"
}        
        
rule r32ac659d0f4233bc4bf98ada3f550406 {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.82 64bit (2018-02-05 09:24:10)"
        author = "@viql"
        date = "2018-07-19"
        sample = "32ac659d0f4233bc4bf98ada3f550406"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 753664 and
        hash.md5(0,filesize) ==  "32ac659d0f4233bc4bf98ada3f550406"
}        
        
rule r1daa6d0c122f78d2069b5df536e26508 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.60 64bit (2017-06-28 21:58:25)"
        author = "@viql"
        date = "2018-07-19"
        sample = "1daa6d0c122f78d2069b5df536e26508"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 450560 and
        hash.md5(0,filesize) ==  "1daa6d0c122f78d2069b5df536e26508"
}        
        
rule red570695236713a847a81fb62e54f782 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.74 32bit (2017-11-25 13:14:38)"
        author = "@viql"
        date = "2018-07-19"
        sample = "ed570695236713a847a81fb62e54f782"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 348160 and
        hash.md5(0,filesize) ==  "ed570695236713a847a81fb62e54f782"
}        
        
rule r5bb318f28821576e3975b13b9eebf617 {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' version 4.85 32bit (2018-03-23 18:14:41)"
        author = "@viql"
        date = "2018-07-19"
        sample = "5bb318f28821576e3975b13b9eebf617"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "5bb318f28821576e3975b13b9eebf617"
}        
        
rule r3113f7ca01b174211eae1a3a8f1614df {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.85 32bit (2018-03-11 07:48:14)"
        author = "@viql"
        date = "2018-07-19"
        sample = "3113f7ca01b174211eae1a3a8f1614df"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "3113f7ca01b174211eae1a3a8f1614df"
}        
        
rule r1dcfab5e9a43ce0320bf05e2bed0e8f3 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.72 32bit (2017-11-16 10:49:17)"
        author = "@viql"
        date = "2018-07-19"
        sample = "1dcfab5e9a43ce0320bf05e2bed0e8f3"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 352256 and
        hash.md5(0,filesize) ==  "1dcfab5e9a43ce0320bf05e2bed0e8f3"
}        
        
rule r5705837474d6126e8e0781b1656e7415 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.62 32bit (2017-08-03 20:32:06)"
        author = "@viql"
        date = "2018-07-19"
        sample = "5705837474d6126e8e0781b1656e7415"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 352256 and
        hash.md5(0,filesize) ==  "5705837474d6126e8e0781b1656e7415"
}        
        
rule r81f93600a86d319f22a5e5696ef4c92d {
    meta:
        description = "Dridex module: Botnet 10105, module 'bot' version 2.22 64bit (2018-06-17 11:00:18)"
        author = "@viql"
        date = "2018-07-19"
        sample = "81f93600a86d319f22a5e5696ef4c92d"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 712704 and
        hash.md5(0,filesize) ==  "81f93600a86d319f22a5e5696ef4c92d"
}        
        
rule r7b1631b97c029fc6a16fdb20a13854b7 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.86 32bit (2018-06-01 18:49:25)"
        author = "@viql"
        date = "2018-07-19"
        sample = "7b1631b97c029fc6a16fdb20a13854b7"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 507904 and
        hash.md5(0,filesize) ==  "7b1631b97c029fc6a16fdb20a13854b7"
}        
        
rule r0a4ef87b5ab1593121f3e3cfad9ea476 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.85 64bit (2018-03-06 10:05:33)"
        author = "@viql"
        date = "2018-07-19"
        sample = "0a4ef87b5ab1593121f3e3cfad9ea476"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 647168 and
        hash.md5(0,filesize) ==  "0a4ef87b5ab1593121f3e3cfad9ea476"
}        
        
rule r537d5a22641f4816bb566cb505d084f6 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.85 32bit (2018-03-11 07:45:42)"
        author = "@viql"
        date = "2018-07-19"
        sample = "537d5a22641f4816bb566cb505d084f6"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 487424 and
        hash.md5(0,filesize) ==  "537d5a22641f4816bb566cb505d084f6"
}        
        
rule r34488bd593341ca9f1c097f5e7d16e1b {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.86 64bit (2018-05-30 11:11:22)"
        author = "@viql"
        date = "2018-07-19"
        sample = "34488bd593341ca9f1c097f5e7d16e1b"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 659456 and
        hash.md5(0,filesize) ==  "34488bd593341ca9f1c097f5e7d16e1b"
}        
        
rule rb62d54c8bd2c2d6b6b2a6cf81b0fb097 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.61 64bit (2017-07-31 21:36:25)"
        author = "@viql"
        date = "2018-07-19"
        sample = "b62d54c8bd2c2d6b6b2a6cf81b0fb097"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 450560 and
        hash.md5(0,filesize) ==  "b62d54c8bd2c2d6b6b2a6cf81b0fb097"
}        
        
rule rc10409766fd8f1cd80d1113b9bee4a67 {
    meta:
        description = "Dridex module: Botnet 10105, module 'bot' version 2.22 32bit (2018-06-11 09:30:11)"
        author = "@viql"
        date = "2018-07-19"
        sample = "c10409766fd8f1cd80d1113b9bee4a67"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 577536 and
        hash.md5(0,filesize) ==  "c10409766fd8f1cd80d1113b9bee4a67"
}        
        
rule r0caaae681f61ba974bd5d4a013312ee2 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.67 64bit (2017-10-02 22:23:23)"
        author = "@viql"
        date = "2018-07-19"
        sample = "0caaae681f61ba974bd5d4a013312ee2"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 446464 and
        hash.md5(0,filesize) ==  "0caaae681f61ba974bd5d4a013312ee2"
}        
        
rule r426af8219007ecb11ff8639b2474311d {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.86 32bit (2018-06-06 10:58:04)"
        author = "@viql"
        date = "2018-07-19"
        sample = "426af8219007ecb11ff8639b2474311d"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 536576 and
        hash.md5(0,filesize) ==  "426af8219007ecb11ff8639b2474311d"
}        
        
rule r491cb5e246e51c01d30840ce75a7a8fb {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.83 64bit (2018-02-16 07:07:38)"
        author = "@viql"
        date = "2018-07-19"
        sample = "491cb5e246e51c01d30840ce75a7a8fb"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 692224 and
        hash.md5(0,filesize) ==  "491cb5e246e51c01d30840ce75a7a8fb"
}        
        
rule r7d4ffad425e9cc91c60d817ba42f2c55 {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' version 4.85 64bit (2018-05-01 14:43:04)"
        author = "@viql"
        date = "2018-07-19"
        sample = "7d4ffad425e9cc91c60d817ba42f2c55"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 647168 and
        hash.md5(0,filesize) ==  "7d4ffad425e9cc91c60d817ba42f2c55"
}        
        
rule r70d84ec4cde6323bdce3273870970aba {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' version 4.86 32bit (2018-05-25 13:37:53)"
        author = "@viql"
        date = "2018-07-19"
        sample = "70d84ec4cde6323bdce3273870970aba"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 516096 and
        hash.md5(0,filesize) ==  "70d84ec4cde6323bdce3273870970aba"
}        
        
rule rf13f270b8317358f8ccb339a8c905591 {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' version 4.86 32bit (2018-06-01 18:49:25)"
        author = "@viql"
        date = "2018-07-19"
        sample = "f13f270b8317358f8ccb339a8c905591"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 507904 and
        hash.md5(0,filesize) ==  "f13f270b8317358f8ccb339a8c905591"
}        
        
rule r213861f6c38cf79771a4cc136474bf67 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.73 64bit (2017-11-16 15:02:36)"
        author = "@viql"
        date = "2018-07-19"
        sample = "213861f6c38cf79771a4cc136474bf67"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 471040 and
        hash.md5(0,filesize) ==  "213861f6c38cf79771a4cc136474bf67"
}        
        
rule r08876dbf3845e12e419cbfb9cc99f5cf {
    meta:
        description = "Dridex module: Botnet 3122, module 'bot' version 4.85 32bit (2018-04-27 15:22:32)"
        author = "@viql"
        date = "2018-07-19"
        sample = "08876dbf3845e12e419cbfb9cc99f5cf"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 548864 and
        hash.md5(0,filesize) ==  "08876dbf3845e12e419cbfb9cc99f5cf"
}        
        
rule r5d087ecef12ed735a4f22324cbfc3d70 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.86 32bit (2018-05-29 10:19:55)"
        author = "@viql"
        date = "2018-07-19"
        sample = "5d087ecef12ed735a4f22324cbfc3d70"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 520192 and
        hash.md5(0,filesize) ==  "5d087ecef12ed735a4f22324cbfc3d70"
}        
        
rule r4823da9b1fa44bf06b5a1dfcf52ee03e {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.66 32bit (2017-09-10 16:17:16)"
        author = "@viql"
        date = "2018-07-19"
        sample = "4823da9b1fa44bf06b5a1dfcf52ee03e"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 335872 and
        hash.md5(0,filesize) ==  "4823da9b1fa44bf06b5a1dfcf52ee03e"
}        
        
rule rc2edb307a55b8664b5c7e3f2745d9d64 {
    meta:
        description = "Dridex module: Botnet 7200, module 'bot' version 4.86 64bit (2018-05-28 10:07:56)"
        author = "@viql"
        date = "2018-07-19"
        sample = "c2edb307a55b8664b5c7e3f2745d9d64"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 659456 and
        hash.md5(0,filesize) ==  "c2edb307a55b8664b5c7e3f2745d9d64"
}        
        
rule r0737309e226245feecd27a35f7a50e59 {
    meta:
        description = "Dridex module: Botnet 11122, module 'bot' version 4.14 32bit (2018-06-12 12:57:00)"
        author = "@viql"
        date = "2018-07-19"
        sample = "0737309e226245feecd27a35f7a50e59"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 532480 and
        hash.md5(0,filesize) ==  "0737309e226245feecd27a35f7a50e59"
}        
        
rule r3df2e31681a7e529139a9fed7f733ad6 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.62 64bit (2017-08-20 16:03:51)"
        author = "@viql"
        date = "2018-07-19"
        sample = "3df2e31681a7e529139a9fed7f733ad6"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 454656 and
        hash.md5(0,filesize) ==  "3df2e31681a7e529139a9fed7f733ad6"
}        
        
rule r8bc3faf395280ce664c21bff1e019959 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.82 32bit (2018-02-15 15:18:22)"
        author = "@viql"
        date = "2018-07-19"
        sample = "8bc3faf395280ce664c21bff1e019959"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 483328 and
        hash.md5(0,filesize) ==  "8bc3faf395280ce664c21bff1e019959"
}        
        
rule r303299aca690f1d5de966b542c89e10f {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.66 64bit (2017-09-10 16:17:45)"
        author = "@viql"
        date = "2018-07-19"
        sample = "303299aca690f1d5de966b542c89e10f"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 442368 and
        hash.md5(0,filesize) ==  "303299aca690f1d5de966b542c89e10f"
}        
        
rule r365d8ce82f257d9489a6db7f6cf01517 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.60 64bit (2017-07-09 17:02:37)"
        author = "@viql"
        date = "2018-07-19"
        sample = "365d8ce82f257d9489a6db7f6cf01517"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 450560 and
        hash.md5(0,filesize) ==  "365d8ce82f257d9489a6db7f6cf01517"
}        
        
rule r724058d1cc04c3c3295bcf8d640375b1 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.14 64bit (2018-06-21 09:42:38)"
        author = "@viql"
        date = "2018-07-19"
        sample = "724058d1cc04c3c3295bcf8d640375b1"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 626688 and
        hash.md5(0,filesize) ==  "724058d1cc04c3c3295bcf8d640375b1"
}        
        
rule rbc303564876fb407642032cf93a93058 {
    meta:
        description = "Dridex module: Botnet 4200, module 'bot' version 4.85 64bit (2018-03-11 07:22:01)"
        author = "@viql"
        date = "2018-07-19"
        sample = "bc303564876fb407642032cf93a93058"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "bc303564876fb407642032cf93a93058"
}        
        
rule r641d179561c11bd2f5866247e7430475 {
    meta:
        description = "Dridex module: Botnet 10105, module 'bot' version 2.20 64bit (2018-06-05 07:42:44)"
        author = "@viql"
        date = "2018-07-19"
        sample = "641d179561c11bd2f5866247e7430475"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 700416 and
        hash.md5(0,filesize) ==  "641d179561c11bd2f5866247e7430475"
}        
        
rule rba9472537e6404849dddf9341d155928 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.85 64bit (2018-03-06 22:04:42)"
        author = "@viql"
        date = "2018-07-19"
        sample = "ba9472537e6404849dddf9341d155928"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 643072 and
        hash.md5(0,filesize) ==  "ba9472537e6404849dddf9341d155928"
}        
        
rule rd27b89048aee714e65f506bf744493d6 {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.59 64bit (2017-06-26 06:06:22)"
        author = "@viql"
        date = "2018-07-19"
        sample = "d27b89048aee714e65f506bf744493d6"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 450560 and
        hash.md5(0,filesize) ==  "d27b89048aee714e65f506bf744493d6"
}        
        
rule r2ef3236e531301a52756d262c7a3249f {
    meta:
        description = "Dridex module: Botnet 2144, module 'bot' version 4.82 64bit (2018-02-14 09:17:49)"
        author = "@viql"
        date = "2018-07-19"
        sample = "2ef3236e531301a52756d262c7a3249f"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 651264 and
        hash.md5(0,filesize) ==  "2ef3236e531301a52756d262c7a3249f"
}        
        
rule rf41fb1019007c5e03ff3d38ee91523dd {
    meta:
        description = "Dridex module: Botnet 23005, module 'bot' version 4.85 64bit (2018-03-11 07:48:28)"
        author = "@viql"
        date = "2018-07-19"
        sample = "f41fb1019007c5e03ff3d38ee91523dd"
    strings:
        $m0 = { 4d 5a }
    condition:
        $m0 at 0 and
        filesize == 630784 and
        hash.md5(0,filesize) ==  "f41fb1019007c5e03ff3d38ee91523dd"
}        
        
