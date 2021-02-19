pipeline{
    
    agent any
    
    stages{
        
        stage('gitcheckout'){
            steps{
                git branch: 'main', credentialsId: 'git-credentials', url: 'https://github.com/MuppiriTendulkar/python-pylint.git'
            }
            
        }
        
        stage('build docker image') {
            steps{
                sh 'docker build -t tendulkar999/python-pylint:5 .'
            }
            
        }
