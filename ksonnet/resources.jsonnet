
//
// Definition for dynamic detector worker
//

// Import KSonnet library.
local k = import "ksonnet.beta.3/k.libsonnet";
local tnw = import "lib/tnw-common.libsonnet";

// Short-cuts to various objects in the KSonnet library.
local depl = k.apps.v1beta2.deployment;
local deployMixin = depl.mixin;
local deployMetadata = deployMixin.metadata;
local hpa = k.autoscaling.v1.horizontalPodAutoscaler;
local container = depl.mixin.spec.template.spec.containersType;
local containerPort = container.portsType;
local mount = container.volumeMountsType;
local volume = depl.mixin.spec.template.spec.volumesType;
local env = container.envType;
local secretDisk = volume.mixin.secret;
local svc = k.core.v1.service;
local svcPort = svc.mixin.spec.portsType;
local tnw = import 'lib/tnw-common.libsonnet';
local readinessProbe = container.mixin.readinessProbe;
local resources = container.mixin.resources;

local worker(config) = {

	local version = import "version.jsonnet",

	local pgm = "analytics-dynamic-detector",

	name: pgm,
	namespace: config.namespace,
	labels: {app: pgm, component: "analytics"},
	
	images: [config.containerBase + "/analytics-dynamic-detector:" + version],

	input: config.workers.queues.dynamicdetector.input,
	output: config.workers.queues.dynamicdetector.output,

	// Environment variables
	envs:: [
		env.new("AMQP_BROKER", "amqp://guest:guest@amqp:5672"),
		env.new("AMQP_ALERT_EXCHANGE", "alerts"),
	],

	ports:: [
		containerPort.newNamed("initial-load", 8081),
	],

	// Container definition.
	containers:: [
		container.new($.name, $.images[0])
			.withEnv($.envs)
			.withArgs([$.input] +
						   std.map(function(x) "output:" + x,
								   $.output))
      .withPorts($.ports) +
      resources
        .withLimits({memory: "2048M", cpu: "0.7"})
        .withRequests({memory: "1024M", cpu: "0.65"})
	],

	// Deployment definition.  replicas is number of container replicas,
	// inp is the input queue name, out is an array of output queue names.
	deployments:: [
		depl.new($.name,
				config.workers.replicas.dynamicdetector.min,
				$.containers,
				$.labels) +
				deployMixin.metadata.withNamespace($.namespace) +
				deployMixin.spec.template.metadata.withAnnotations({
					"prometheus.io/scrape": "true",
					"prometheus.io/port": "8080"
				}) +
				deployMixin.spec.withMinReadySeconds(10) +
				deployMixin.spec.strategy.rollingUpdate.withMaxUnavailable(2) +
				deployMixin.spec.selector
					.withMatchLabels($.labels)
	],

	// Ports declared on the service.
	svcPorts:: [
		svcPort.newNamed("initial-load", 8081, 8081),
	],

	services:: [
		svc.new("dynamicdetector", $.labels, $.svcPorts) +
			svc.mixin.metadata
				.withNamespace($.namespace)
				.withLabels($.labels)
	],
  
  poddisruption:: [
    tnw.podDisruptionBudget($.name, 2, $.labels, $.namespace)
  ],
  
	autoScalers:: [
		tnw.customHorizontalPodAutoscaler(
			$.name,
			$.labels,
			config.workers.replicas.dynamicdetector.min,
			config.workers.replicas.dynamicdetector.max,
			[
				{name: "rabbitmq_queue_messages_unacknowledged", target: 50},
				{name: "cpu", target: 20},
			],
			$.namespace
		)
	],

	resources:
		if config.options.includeAnalytics then
			$.deployments + $.services + $.autoScalers + $.poddisruption
		else [],

};

[worker]
