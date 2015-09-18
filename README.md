# karmafeast-cert_pfxcertificate

pfx file import to cert stores on windows via powershell.  

**removal via ensure => absent and thumbprint match.**  

**need cert thumbprint for unless comparison in ensure => present**

example use:
    
    class dogfood{
    
    cert_pfxcertificate::import { 'www server cert':
    	certpath  => "c:\\temp\\mycert.pfx",
    	certrootstore => 'LocalMachine',
    	certstore => 'My',
    	ensure=> 'present',
    	thumbprint=> '9111B22233387444855556663777786888269996',
    	certpassword  => hiera('cert::my_www_com::pfxpw'),
      }
    
    cert_pfxcertificate::import { 'www server cert removal':
    	certrootstore => 'LocalMachine',
    	certstore => 'My',
    	ensure=> 'absent',
    	thumbprint=> '9111B22233387444855556663777786888269996',
      }
    
    }
