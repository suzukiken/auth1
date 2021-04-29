#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from '@aws-cdk/core';
import { Auth1Stack } from '../lib/auth1-stack';

const app = new cdk.App();
new Auth1Stack(app, 'Auth1Stack', {
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION }
});
