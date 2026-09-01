import * as Alchemy from "alchemy";
import * as AWS from "alchemy/AWS";
import * as Effect from "effect/Effect";
import { resolve } from "node:path";

const repository = resolve(import.meta.dirname, "../..");
const dockerContext = process.env.BENCH_DOCKER_CONTEXT ?? repository;

export default Alchemy.Stack(
  "Minip2pBench",
  {
    providers: AWS.providers(),
    state: AWS.state({ prefix: "minip2p" }),
  },
  Effect.gen(function* () {
    const cluster = yield* AWS.ECS.Cluster("Cluster", {
      clusterName: "minip2p-bench",
      settings: [{ name: "containerInsights", value: "disabled" }],
      tags: { project: "minip2p", purpose: "benchmark" },
    });

    const task = yield* AWS.ECS.Task("Task", {
      taskName: "minip2p-bench",
      context: dockerContext,
      dockerfile: resolve(dockerContext, "infra/bench/Dockerfile"),
      cpu: 2048,
      memory: 4096,
      runtimePlatform: {
        cpuArchitecture: "X86_64",
        operatingSystemFamily: "LINUX",
      },
      container: {
        linuxParameters: {
          capabilities: { add: ["SYS_PTRACE"] },
        },
      },
      tags: { project: "minip2p", purpose: "benchmark" },
    });

    return {
      clusterArn: cluster.clusterArn,
      taskDefinitionArn: task.taskDefinitionArn,
      containerName: task.containerName,
      logGroupName: task.logGroupName,
    };
  }),
);
