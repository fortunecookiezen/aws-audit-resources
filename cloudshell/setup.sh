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

for file in ~/.bashrc.d/*; do
    if [[ -f $file ]]; then
        . "$file"
    fi
done

if [[ -f ~/.zshrc]]; then
    echo "Zsh configuration file found, moving it."
    mv ~/.zshrc ~/.zshrc.bak
    echo "Zsh configuration file backed up to ~/.zshrc.bak" 
else
    echo "No Zsh configuration file found, skipping."
fi
# Create a new .zshrc file with the necessary configurations
cat <<'EOF' >> ~.zshrc
# Amazon Q pre block. Keep at the top of this file.
[[ -f "${HOME}/.local/share/amazon-q/shell/zshrc.pre.zsh" ]] && builtin source "${HOME}/.local/share/amazon-q/shell/zshrc.pre.zsh"

# completion
autoload -U compinit
zstyle ':completion:*:descriptions' format '%U%B%d%b%u'
zstyle ':completion:*:warnings' format '%BSorry, no matches for: %d%b'
compinit

#allow tab completion in the middle of a word
setopt COMPLETE_IN_WORD

# correction
setopt correctall prompt_subst

# a function
parse_git_branch() {
     git branch 2> /dev/null | sed -e '/^[^*]/d' -e 's/* \(.*\)/ (\1)/'
}

get_region() {
    if [[ -v AWS_REGION ]]; then
        echo $AWS_REGION
    fi
}

# destroys aws credentials in the shell
destroy_aws_role_profile() {
 for i in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN;
 do
    unset $i;
 done
}

# allows you to easily assume role and export credentials to the shell
assume_aws_role() {
    session=$(aws sts assume-role --role-arn ${1:?"role arn must be specified"} \
    --role-session-name $USER --query "Credentials.[AccessKeyId, SecretAccessKey, SessionToken"] | jq -r ".[]")
    keys=(${(f)session}) #creates an array from the javascript output
    access_key=$keys[1]
    secret_key=$keys[2]
    session_token=$keys[3]
    export AWS_ACCESS_KEY_ID=$access_key
    export AWS_SECRET_ACCESS_KEY=$secret_key
    export AWS_SESSION_TOKEN=$session_token
}

autoload -Uz compinit && compinit
autoload bashcompinit && bashcompinit
complete -C '/usr/local/bin/aws_completer' aws

# actual prompt
PROMPT='[%n@%m] %c %F{green}$(parse_git_branch)%f %F{214}$(get_region)%f $ '

# Amazon Q post block. Keep at the bottom of this file.
[[ -f "${HOME}/.local/share/amazon-q/shell/zshrc.post.zsh" ]] && builtin source "${HOME}/.local/share/amazon-q/shell/zshrc.post.zsh"
EOF

# install terraform
sudo yum install -y yum-utils shadow-utils
sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
sudo yum -y install terraform
terraform -install-autocomplete

# install iam-collect and iam-lens
npm install -g @cloud-copilot/iam-collect --prefix .
npm install -g @cloud-copilot/iam-lens --prefix .

echo "done with setup.sh, paste the following into your shell to complete terminal setup:
 source .bashrc.d/bashrc "
