## RStudio Connect Plugin for Fluent Bit

This repository contains a standalone [Fluent Bit](https://fluentbit.io/) filter
plugin for forwarding application logs from an [RStudio
Connect](https://www.rstudio.com/products/connect/) instance. It works by
watching for new logs written to the `jobs` directory and querying the Connect
API for additional metadata to link these logs back to specific applications.

Fluent Bit can then be used to forward the results to any of its [supported
backends](https://docs.fluentbit.io/manual/pipeline/outputs), including
Elasticsearch, Splunk, Stackdriver, Cloudwatch Logs, Datadog, Loki, and many
others.

This should allow R users to easily export logs to their organisation's existing
logging provider without needing to modify their reports or Shiny apps to do so.

Warning: this plugin is an unstable work-in-progress that relies on undocumented
Connect APIs.

## Installation

The plugin currently must be built from source. For instructions to install
Fluent Bit itself on your Connect instance, see [its
documentation](https://docs.fluentbit.io/manual/installation/getting-started-with-fluent-bit).

## Building

Requirements:

* Fluent Bit's [source code]()
* A C compiler
* CMake 2.8 or later

Since Connect [only runs on
Linux](https://docs.rstudio.com/connect/admin/#system-requirements), that is the
platform you will be targeting.

Clone the repository and build the plugin as follows:

``` shell
$ mkdir build && cd build
$ cmake -DFLB_SOURCE=/path/to/fluent-bit -DPLUGIN_NAME=filter_rsconnect ../
$ make
```

This will create a `flb-filter_rsconnect.so` file that must be copied to the
server running your Connect instance.

## Configuration

The following is a sample Fluent Bit configuration using this filter plugin:

``` ini
[SERVICE]
    Flush        5
    Daemon       Off
    Log_Level    info
    Parsers_File parsers.conf
    Plugins_File plugins.conf

[INPUT]
    Name         tail
    Tag          rsconnect.*
    Path         /mnt/rstudio-connect/jobs/*/*/job.std*
    # Optional, see below.
    Parser       rsconnect
    # Optional but highly recommended.
    Ignore_Older 1h

[FILTER]
    Name    rsconnect
    Match   rsconnect.*
    # API settings should match your Connect instance.
    Api_Url http://localhost:3939
    Api_Key rCliECUlqwMH85CRWt5ZC9DY90Bab375
    # HTTP client settings, all optional.
    Buffer_Size 4K
    tls.verify On

[OUTPUT]
    # This is purely for demostration purposes, you'll want to use
    # a real output plugin in practice.
    Name  stdout
    Match *
```

You must also provide a `plugins.conf` file pointing to the compiled plugin,
such as:

``` ini
[PLUGINS]
    Path /opt/td-agent-bit/flb-filter_rsconnect.so
```

The following entry may also be useful in your `parsers.conf` -- it can be used
to extract the timestamps from Connect's standard logging format:

``` ini
[PARSER]
    Name        rsconnect
    Format      regex
    Regex       ^(?<time>[^ ]+ [^ ]+) (?<message>.*)$
    Time_Key    time
    Time_Keep   Off
    Time_Format %Y/%m/%d %H:%M:%S.%L
```
