# Introduction

Based on code from https://github.com/letsencrypt/boulder.

# Usage

Download https://www.gstatic.com/ct/log_list/v3/log_list.json to any path in the filesystem.

Then invoke the linter with a command like this where the certificate currently needs to be DER encoded:

```
wisekey-zlint certificate.cer log_list.json
```

## Integration with EJBCA

*Note that EJBCA itself checks the SCTs signatures, so there is no need for this linter to do it.*  

Configuration:
- Full pathname of script: `/path/to/wisekey-zlint /path/to/log_list.json`
- Issuance Phase: Certificate Validation

# TODOS 

- Study https://github.com/zmap/zlint#library-usage when coming back to this project.
- Support to execute all SSL checks required by WISeKey, both for pre-issuance and post-issuance.
- Determine how safe it is really to use only ZLint for SSL certificates linting and stop using any other linter. See https://groups.google.com/g/mozilla.dev.security.policy/c/RH5oRS8ZbXo
- Determine how the log_list.json is going to be kept updated. Initially it could be updated with a cron task.
- Consider the Apple CT policy too. Maybe with another lint (or multiple linters). Note that its effective date is different than the Google's one.

# Test
Lorem ipsum dolor sit amet consectetur adipiscing elit lectus hendrerit porta curae feugiat, odio ridiculus fermentum