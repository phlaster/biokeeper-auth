from user_agents import  parse

def parse_user_agent(user_agent_string):
    user_agent = parse(user_agent_string)
    return ', '.join(i for i in [
        user_agent.browser.family if user_agent.browser.family != 'Other' else '',
        user_agent.os.family if user_agent.os.family != 'Other' else '',
        user_agent.device.family if user_agent.device.family != 'Other' else ''
    ] if i != '')