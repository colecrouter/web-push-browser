module.exports = {
	preset: "ts-jest",
	testEnvironment: "node",
	resolver: "ts-jest-resolver",
	transform: {
		".ts": [
			"ts-jest",
			{
				isolatedModules: true,
			},
		],
	},
};
