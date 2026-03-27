# Shared Technology and WAF Signatures

WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
    "Akamai": ["akamai-ghost", "akamaighost", "x-akamai"],
    "Sucuri": ["x-sucuri", "sucuri"],
    "Imperva": ["incapsula", "visid_incap", "nlbi_"],
    "AWS WAF": ["x-amz-cf-id", "awswaf"],
    "Barracuda": ["barra_counter_scope", "bni_persistence"],
    "F5 BIG-IP": ["bigipserver", "mrhtool", "f5_cspm"],
    "Fortinet": ["fortiweb", "fortigate"],
    "ModSecurity": ["mod_security", "no-cache=\"set-cookie\""],
    "DenyAll": ["sessioncookie=", "denyall"],
    "Radware": ["x-sl-compid", "x-rdw-"]
}

TECH_SIGNATURES = {
    "Server": {
        "nginx": "Nginx",
        "apache": "Apache",
        "litespeed": "LiteSpeed",
        "iis": "Microsoft IIS",
        "gws": "Google Web Server",
        "werkzeug": "Werkzeug/Python",
        "kestrel": "ASP.NET Kestrel",
        "glassfish": "Oracle GlassFish",
        "jetty": "Eclipse Jetty"
    },
    "Framework": {
        "express": "Node/Express",
        "next.js": "Next.js",
        "php": "PHP",
        "laravel": "Laravel",
        "django": "Django",
        "flask": "Flask",
        "rails": "Ruby on Rails",
        "spring": "Spring Boot",
        "asp.net": "ASP.NETCore",
        "symfony": "Symfony",
        "vue": "Vue.js",
        "react": "React",
        "angular": "Angular"
    },
    "CMS": {
        "wordpress": "WordPress",
        "drupal": "Drupal",
        "joomla": "Joomla",
        "ghost": "Ghost",
        "magento": "Magento",
        "shopify": "Shopify"
    }
}
