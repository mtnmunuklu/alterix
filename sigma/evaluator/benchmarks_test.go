package evaluator_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"Alterix/sigma"
	"Alterix/sigma/evaluator"
)

const testRule = `
title: Suspicious PsExec Execution - Zeek
id: f1b3a22a-45e6-4004-afb5-4291f9c21166
related:
  - id: c462f537-a1e3-41a6-b5fc-b2c2cef9bf82
    type: derived
status: test
description: detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one
references:
  - https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html
author: Samir Bousseaden, @neu5ron, Tim Shelton
date: 2020/04/02
modified: 2022/12/27
tags:
  - attack.lateral_movement
  - attack.t1021.002
logsource:
  product: zeek
  service: smb_files
detection:
  selection:
    path|contains|all:
      - '\\'
      - '\IPC$'
    name|endswith:
      - '-stdin'
      - '-stdout'
      - '-stderr'
  filter:
    name|startswith: 'PSEXESVC'
  condition: selection and not filter
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
    conditions:
      EventID: 1
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

const testEvent = `
{
	"foo": "foobarbaz",
	"foobar": {
		"baz": "baz"
	},

	"comment": "// random JSON from json-generator.com for more realistic payload size",
    "_id": "60d0b4610f3d918f1790f96a",
    "index": 0,
    "guid": "7d9e0be8-a58c-4295-9716-95828f02c464",
    "isActive": true,
    "balance": "$2,710.89",
    "picture": "http://placehold.it/32x32",
    "age": 40,
    "eyeColor": "blue",
    "name": "Althea Gonzalez",
    "gender": "female",
    "company": "EXOTERIC",
    "email": "altheagonzalez@exoteric.com",
    "phone": "+1 (890) 600-3120",
    "address": "482 Highland Avenue, Garfield, Northern Mariana Islands, 2968",
    "about": "Aliqua culpa proident deserunt dolor sint non. Ea exercitation duis eu elit. Laborum exercitation reprehenderit velit eu eu occaecat duis. Id qui veniam ea sint fugiat do occaecat ut duis laboris.\r\n",
    "registered": "2019-07-16T01:45:06 -01:00",
    "latitude": -8.51841,
    "longitude": 133.547791,
    "tags": [
      "quis",
      "duis",
      "in",
      "fugiat",
      "laborum",
      "incididunt",
      "elit"
    ],
    "friends": [
      {
        "id": 0,
        "name": "Ursula Velez"
      },
      {
        "id": 1,
        "name": "Cecelia Alvarado"
      },
      {
        "id": 2,
        "name": "Mooney Mullen"
      }
    ],
    "greeting": "Hello, Althea Gonzalez! You have 7 unread messages.",
    "favoriteFruit": "apple"
}
`

func BenchmarkRuleEvaluator_Matches(b *testing.B) {
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

	b.Run("DecodeAndMatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var event map[string]interface{}
			if err := json.Unmarshal([]byte(testEvent), &event); err != nil {
				b.Fatal(err)
			}
			result, err := r.Matches(ctx, event)
			if err != nil {
				b.Fatal(err)
			}
			if !result.Match {
				b.Fatal("event should have matched")
			}
		}
	})
	b.Run("JustMatch", func(b *testing.B) {
		var event map[string]interface{}
		if err := json.Unmarshal([]byte(testEvent), &event); err != nil {
			b.Fatal(err)
		}
		for i := 0; i < b.N; i++ {
			result, err := r.Matches(ctx, event)
			if err != nil {
				b.Fatal(err)
			}
			if !result.Match {
				b.Fatal("event should have matched")
			}
		}
	})
}

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
