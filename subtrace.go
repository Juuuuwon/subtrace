// Copyright (c) Subtrace, Inc.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/peterbourgon/ff/v3/ffcli"
)

func main() {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
        config.WithRegion(os.Getenv("AWS_REGION_NAME")),
        config.WithCredentialsProvider(aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
            return aws.Credentials{
                AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
                SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
            }, nil
        })),
    )
    if err != nil {
        return
    }

	client := cloudwatchlogs.NewFromConfig(cfg)

	// 로그 그룹이 존재하는지 확인하고, 없으면 생성
	output, err := client.DescribeLogGroups(context.TODO(), &cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: aws.String("/proxy-logging"),
	})
	if err != nil {
		return
	}

	if len(output.LogGroups) == 0 {
		// 로그 그룹이 없으면 새로 생성
		_, err = client.CreateLogGroup(context.TODO(), &cloudwatchlogs.CreateLogGroupInput{
			LogGroupName: aws.String("/proxy-logging"),
		})
		if err != nil {
			return 
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := new(ffcli.Command)
	c.Name = filepath.Base(os.Args[0])
	c.ShortUsage = "subtrace <command>"
	c.Subcommands = subcommands

	c.FlagSet = flag.NewFlagSet("subtrace", flag.ContinueOnError)
	c.FlagSet.SetOutput(os.Stdout)
	c.Exec = func(ctx context.Context, args []string) error {
		fmt.Fprintf(os.Stdout, "%s\n", c.UsageFunc(c))

		// Using os.Args and not args[0] because `subtrace -- curl` calls Exec with
		// args={"curl"}, not args={"--", "curl"}. The real error is the lack of
		// the run subcommand (explicit is better than implicit).
		if len(os.Args) >= 2 {
			return fmt.Errorf("unknown command %q", os.Args[1])
		}
		return nil
	}

	switch err := c.Parse(os.Args[1:]); {
	case err == nil:
	case errors.Is(err, flag.ErrHelp):
		return
	case strings.Contains(err.Error(), "flag provided but not defined"):
		os.Exit(2)
	default:
		fmt.Fprintf(os.Stderr, "subtrace: error: %v\n", err)
		os.Exit(1)
	}

	if err := c.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "subtrace: error: %v\n", err)
		os.Exit(1)
	}
}
