package io.spring.gradle.propdeps

import org.gradle.api.Plugin
import org.gradle.api.Project

class PropDepsPlugin implements Plugin<Project> {
	void apply(Project project) {
		project.configurations {
			optional
			provided
		}
		project.sourceSets.main {
			compileClasspath += project.configurations.optional + project.configurations.provided
		}
		project.sourceSets.test {
			compileClasspath += project.configurations.optional + project.configurations.provided
			runtimeClasspath += project.configurations.optional + project.configurations.provided
		}
	}
}
