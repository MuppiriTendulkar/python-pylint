pipeline {
    agent any
        stages {
            stage('pylint') {
                agent {
                    docker { image 'tendulkar999/python-pylint:5' }
                }
                steps {
                    sh 'pylint --version'
                    sh 'git --version'
                }
            }
        }
    }
