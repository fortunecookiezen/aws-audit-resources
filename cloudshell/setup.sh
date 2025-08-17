#!/usr/bin/env bash
# cloudshell/setup.sh
# Setup script for AWS CloudShell environment
mkdir -p ~/bin ~/.bashrc.d

cat <<'EOF' >> ~/.bashrc.d/bashrc
# ~/.bashrc.d/bashrc
# This file is sourced by ~/.bashrc to set up the environment for AWS CloudShell
# shell functions
parse_git_branch() {
        git branch 2> /dev/null | sed -e '/^[^*]/d' -e 's/* \(.*\)/ (\1)/'
}
get_aws_region() {
        if [[ -v AWS_REGION ]]; then
                echo $AWS_REGION
        fi
}
export PS1="[\u@\h \W]\e[1;32m\$(parse_git_branch)\e[0m \e[1;33m\$(get_aws_region)\e[0m $ "
PATH=$PATH:$HOME/.local/bin:$HOME/bin

export PATH
EOF

source ~/.bashrc.d/bashrc

# install terraform
sudo yum install -y yum-utils shadow-utils
sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
sudo yum -y install terraform
terraform -install-autocomplete

# install nodejs
sudo yum install -y nodejs
npm install -g cfn-lint
