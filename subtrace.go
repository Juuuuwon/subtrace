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

// ensureLogGroup는 지정된 이름의 로그 그룹이 존재하는지 확인하고 없으면 생성합니다.
func ensureLogGroup(client *cloudwatchlogs.Client, logGroupName string) error {
    // 로그 그룹이 존재하는지 확인
    output, err := client.DescribeLogGroups(context.TODO(), &cloudwatchlogs.DescribeLogGroupsInput{
        LogGroupNamePrefix: aws.String(logGroupName),
    })
    if err != nil {
        return err
    }

    // 로그 그룹이 없으면 생성
    if len(output.LogGroups) == 0 {
        _, err = client.CreateLogGroup(context.TODO(), &cloudwatchlogs.CreateLogGroupInput{
            LogGroupName: aws.String(logGroupName),
        })
        if err != nil {
            return err
        }
    }
    return nil
}

func main() {
    // 환경 변수 체크
    requiredEnvVars := []string{
        "AWS_REGION_NAME",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
    }
    
    for _, envVar := range requiredEnvVars {
        if os.Getenv(envVar) == "" {
            fmt.Fprintf(os.Stderr, "subtrace: error: required environment variable %q is not set\n", envVar)
            os.Exit(1)
        }
    }

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
        fmt.Fprintf(os.Stderr, "subtrace: error: failed to load AWS config: %v\n", err)
        os.Exit(1)
    }

    client := cloudwatchlogs.NewFromConfig(cfg)

    // 로그 그룹 확인 및 생성
    if err := ensureLogGroup(client, "/proxy-logging"); err != nil {
        fmt.Fprintf(os.Stderr, "subtrace: error: failed to ensure log group: %v\n", err)
        os.Exit(1)
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