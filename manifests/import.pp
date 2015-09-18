# import a pfx certificate - !CERT THUMBPRINT REQUIRED!
# certstore -
# AddressBook          certificate store for other users.
# AuthRoot             certificate store for third-party certificate authorities (CAs).
# CA                   certificate store for intermediate certificate authorities (CAs).
# Disallowed           certificate store for revoked certificates.
# My                   certificate store for personal certificates.
# Root                 certificate store for trusted root certificate authorities (CAs).
# TrustedPeople        certificate store for directly trusted people and resources.
# TrustedPublisher     certificate store for directly trusted publishers.
define cert_pfxcertificate::import (
  $certpath      = '', # path to certificate file to import
  $certrootstore = 'LocalMachine',
  $certstore     = 'My',
  $ensure        = 'present',
  $thumbprint, # thumbprint required
  $certpassword  = '',) {
  validate_re($ensure, '^(present|import|absent)$', 'ensure must be one of \'present\', \'import\', \'absent\'')
  validate_re($certrootstore, '^(LocalMachine|CurrentUser)$', 'certrootstore must be one of \'LocalMachine\', \'CurrentUser\'')
  validate_re($certstore, '^(AddressBook|AuthRoot|CA|Disallowed|My|Root|TrustedPeople|TrustedPublisher)$', 'certstore must be one of \'AddressBook\', \'AuthRoot\', \'CA\', \'Disallowed\', \'My\', \'Root\', \'TrustedPeople\', \'TrustedPublisher\''
  )

  if (empty($thumbprint)) {
    fail('need thumbprint of cert to ensure')
  }

  if (empty($certpath)) {
    fail('cannot ensure present when certpath empty')
  }

  if ($ensure in [
    'present',
    'import']) {
    if (empty($certpassword)) {
      exec { "IMPORT CERT FROM pfx file - ${certpath} - ${title}":
        command   => "Import-PfxCertificate -FilePath \"${certpath}\" -certStoreLocation cert:\\${certrootstore}\\${certstore}",
        provider  => powershell,
        unless    => "\$store = new-object System.Security.Cryptography.X509Certificates.X509Store(\"${certstore}\",\"${certrootstore}\");\$store.open(\"MaxAllowed\");\$found = \$false;foreach(\$c in \$store.Certificates){if(\$c.thumbprint -eq \"${thumbprint}\"){\$found = \$true;break;}}if(\$found){exit 0;}else{exit 1;}",
        logoutput => true,
      }
    } else {
      exec { "IMPORT CERT FROM pfx file with PW - ${certpath} - ${title}":
        command   => "\$mypwd = ConvertTo-SecureString -String \"${certpassword}\" -AsPlainText -Force;Import-PfxCertificate -FilePath \"${certpath}\" -certStoreLocation cert:\\${certrootstore}\\${certstore} -Password \$mypwd",
        provider  => powershell,
        unless    => "\$store = new-object System.Security.Cryptography.X509Certificates.X509Store(\"${certstore}\",\"${certrootstore}\");\$store.open(\"MaxAllowed\");\$found = \$false;foreach(\$c in \$store.Certificates){if(\$c.thumbprint -eq \"${thumbprint}\"){\$found = \$true;break;}}if(\$found){exit 0;}else{exit 1;}",
        logoutput => true,
      }

    }

  }

  # string validation on others is going to be in the 'absent' category - reset to defaults
   else {
    # remove cert if thumbprint match
    exec { "REMOVE CERT BY MATCH THUMBPRINT - ${thumbprint} - ${title}":
      command   => "\$store = new-object System.Security.Cryptography.X509Certificates.X509Store(\"${certstore}\",\"${certrootstore}\");\$store.open(\"MaxAllowed\");foreach(\$c in \$store.Certificates){if(\$c.thumbprint -eq \"${thumbprint}\"){\$store.Remove(\$c);break;}}",
      provider  => powershell,
      unless    => "\$store = new-object System.Security.Cryptography.X509Certificates.X509Store(\"${certstore}\",\"${certrootstore}\");\$store.open(\"MaxAllowed\");\$found = \$false;foreach(\$c in \$store.Certificates){if(\$c.thumbprint -eq \"${thumbprint}\"){\$found = \$true;break;}}if(\$found){exit 1;}else{exit 0;}",
      logoutput => true,
    }
  }
}
