package evaluator_test

import (
	"context"
	"fmt"
	"testing"

	"Alterix/sigma"
	"Alterix/sigma/evaluator"
)

const testRule = `
title: Chafer Activity
id: ce6e34ca-966d-41c9-8d93-5b06c8b97a06
#related:
#  - id: 53ba33fd-3a50-4468-a5ef-c583635cfa92
#    type: derived
description: Detects Chafer activity attributed to OilRig as reported in Nyotron report in March 2018
status: test
references:
  - https://nyotron.com/nyotron-discovers-next-generation-oilrig-attacks/
tags:
  - attack.persistence
  - attack.g0049
  - attack.t1053.005
  - attack.s0111
  - attack.t1543.003
  - attack.defense_evasion
  - attack.t1112
  - attack.command_and_control
  - attack.t1071.004
date: 2018/03/23
modified: 2021/09/19
author: Florian Roth, Markus Neis, Jonhnathan Ribeiro, Daniil Yugoslavskiy, oscd.community
logsource:
  category: process_creation
  product: windows
detection:
  selection_process0:
    CommandLine|contains: '\Service.exe'
    CommandLine|endswith:
      - 'i'
      - 'u'
  selection_process1:
    - CommandLine|endswith: '\microsoft\Taskbar\autoit3.exe'
    - CommandLine|startswith: 'C:\wsc.exe'
  selection_process2:
    Image|contains: '\Windows\Temp\DB\'
    Image|endswith: '.exe'
  selection_process3:
    CommandLine|contains|all:
      - '\nslookup.exe'
      - '-q=TXT'
    ParentImage|contains: '\Autoit'
  condition: 1 of selection* | count(Image) by CommandLine > 5
falsepositives:
  - Unknown
level: high
`

const testConfig = `
# Copied from https://github.com/Neo23x0/sigma/blob/d7d9c0e77237b69f8b29c0ed9613c0828da3bc11/tools/config/generic/sysmon.yml
# under license https://github.com/Neo23x0/sigma/blob/master/LICENSE.Detection.Rules.md
title: Conversion of Generic Rules into Sysmon Specific Rules
order: 10
logsources:
  process_creation:
    category: process_creation
    product: windows
    rewrite:
      product: windows
      service: sysmon
  network_connection:
    category: network_connection
    product: windows
    conditions:
      EventID: 3
    rewrite:
      product: windows
      service: sysmon
  dns_query:
    category: dns_query
    product: windows
    conditions:
      EventID: 22
    rewrite:
      product: windows
      service: sysmon
  registry_event:
    category: registry_event
    product: windows
    conditions:
      EventID:
        - 12
        - 13
        - 14
    rewrite:
      product: windows
      service: sysmon
  file_creation:
    category: file_event
    product: windows
    conditions:
      EventID: 11
    rewrite:
      product: windows
      service: sysmon
  process_access:
    category: process_access
    product: windows
    conditions:
      EventID: 10
    rewrite:
      product: windows
      service: sysmon
  image_loaded:
    category: image_load
    product: windows
    conditions:
      EventID: 7
    rewrite:
      product: windows
      service: sysmon
  driver_loaded:
    category: driver_load
    product: windows
    conditions:
      EventID: 6
    rewrite:
      product: windows
      service: sysmon
  process_terminated:
    category: process_termination
    product: windows
    conditions:
      EventID: 5
    rewrite:
      product: windows
      service: sysmon
fieldmappings:
  CommandLine: command
  Image: sproc
`

func BenchmarkRuleEvaluator_Alters(b *testing.B) {
	rule, err := sigma.ParseRule([]byte(testRule))
	if err != nil {
		b.Fatal(err)
	}
	config, err := sigma.ParseConfig([]byte(testConfig))
	if err != nil {
		b.Fatal(err)
	}

	r := evaluator.ForRule(rule, evaluator.WithConfig(config))
	ctx := context.Background()

	b.Run("JustMatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			result, err := r.Alters(ctx)
			if err != nil {
				b.Fatal(err)
			}
			fmt.Printf("result: %v\n", result)
		}
	})
}
