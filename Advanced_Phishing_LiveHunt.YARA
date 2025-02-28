rule Advanced_Phishing_LiveHunt {
    meta:
        author = "Threat Research Team"
        description = "Detects phishing malware tied to LAPSUS$, SocGholish, Lazarus/DPRK, Scattered Spider, etc."
        date = "2025-02-28"
        tlp = "WHITE"
    
    strings:
        // Office Macro Indicators
        $vba_autoopen = /Auto(Open|_Open)/i
        $vba_doc_open = /Document_Open/i
        $vba_wb_open = /Workbook_Open/i
        $vba_ppt_open = /Presentation_Open/i
        $vba_createobj = /CreateObject/i
        $vba_shell_app = /Shell\.Application/i
        $vba_wscript = /WScript\.Shell/i
        $vba_urlmon = /URLDownloadToFileA?/i
        $vba_xmlhttp = /Msxml2\.XMLHTTP/i
        $vba_powershell = /PowerShell/i
        $vba_reg_write = /CreateTextFile|WriteText/i
        $vba_chr_concat = /Chr\(/i
        
        // Malicious Script Indicators (JS, VBS, HTA, LNK)
        $js_eval = /eval\(/i
        $js_unescape = /unescape\(/i
        $js_fromChar = /fromCharCode/i
        $js_activeX = /ActiveXObject/i
        $js_execute = /Execute(Global)?\s*\(/i
        $js_enc_ps = /-enc\s+[A-Za-z0-9+/]{50}/i
        $js_c2_url = /https?:\/\/[A-Za-z0-9._\-]+\//i
        $js_long_str = /[A-Za-z0-9+\/]{100,}/
        
        // PDF/ISO Indicators
        $pdf_js = /\/JavaScript|\/JS/i
        $pdf_openaction = /\/OpenAction/i
        $pdf_embed_file = /\/EmbeddedFile/i
        $iso_lnk_name = /\\.lnk(;1)?/i
        $iso_exe_name = /\\.exe(;1)?/i
        $iso_powershell = /powershell\.exe/i
        
        // Known Malicious Domains & C2
        $dom_lazarus_1 = "markettrendingcenter"
        $dom_lazarus_2 = "lm-career"
        $dom_lazarus_3 = "honehsn.com"
        $dom_socgholish_1 = "rzegzwre.top"
        $dom_scatter_1 = "-sso."
        $dom_generic_fin1 = "login.htm"
        $dom_generic_fin2 = "account-update"
        
        // LOLBins (Living-Off-The-Land Binaries)
        $lolbin_powershell = "powershell" nocase
        $lolbin_mshta = "mshta" nocase
        $lolbin_rundll32 = "rundll32" nocase
        $lolbin_regsvr32 = "regsvr32" nocase
        $lolbin_wscript = "wscript.exe" nocase
        $lolbin_cscript = "cscript.exe" nocase
        $lolbin_bitsadmin = "bitsadmin" nocase
        $lolbin_certutil = "certutil" nocase
        $lolbin_wuauclt = "wuauclt" nocase
        $lolbin_msiexec = "msiexec" nocase
        $lolbin_installutil = "installutil" nocase
        $lolbin_schtasks = "schtasks" nocase
        
        // Lure Keywords
        $lure_invoice = /Invoice|Payment/i
        $lure_bank = /Bank\s+Statement|Wire Transfer/i
        $lure_job = /Resume|CV|Job\s?Offer/i
    
    condition:
        (
            // Office Documents
            (uint32(0) == 0x504B0304 or uint32(0) == 0x2142444E) and 
            (any of ($vba_*) and (any of ($lolbin_*) or any of ($dom_*) or any of ($js_long_str, $vba_chr_concat) or any of ($lure_*)))
        ) or 
        (
            // Malicious Scripts (JS, VBS, LNK)
            (ext matches /(js|jse|vbs|lnk)$/i and any of ($js_*) and (any of ($lolbin_*) or any of ($dom_*) or $js_long_str or $js_enc_ps))
        ) or 
        (
            // PDFs with malicious script/embedded objects
            (ext matches /pdf$/i and ($pdf_js or $pdf_openaction or $pdf_embed_file) and (any of ($dom_*) or any of ($lolbin_*) or any of ($lure_*)))
        ) or 
        (
            // ISO files with embedded executables
            (ext matches /iso$/i and ($iso_lnk_name or $iso_exe_name) and (any of ($lolbin_*) or any of ($dom_*) or $iso_powershell))
        )
}
