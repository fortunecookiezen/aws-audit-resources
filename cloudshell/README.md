# Using Cloudshell as your audit tool

## execute setup.sh

curl -fsSL https://raw.githubusercontent.com/fortunecookiezen/aws-audit-resources/refs/heads/main/cloudshell/setup.sh | bash -

## .bashrc.d/bashrc

```bash
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
```

## install terraform

```bash
sudo yum install -y yum-utils shadow-utils
sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
sudo yum -y install terraform
```
