from graphviz import Digraph

# Create a directed graph (flowchart)
dot = Digraph(comment='EigenGuard One-Semester Flowchart', format='png')

# Set graph attributes for compact layout
dot.attr(rankdir='TB', size='8,10')

# Nodes
dot.node('start', 'Start', shape='ellipse', style='filled', fillcolor='lightblue')
dot.node('plan', 'Weeks 1-2:\nPlanning & Research', shape='box')
dot.node('data', 'Weeks 3-5:\nData & Model Prep', shape='box')
dot.node('dev', 'Weeks 6-10:\nSystem Development', shape='box')
dot.node('test', 'Weeks 11-14:\nIntegration & Testing', shape='box')
dot.node('end', 'Weeks 15-16:\nFinalization', shape='ellipse', style='filled', fillcolor='lightgreen')

# Edges
dot.edge('start', 'plan', label='Begin')
dot.edge('plan', 'data', label='Plan Done')
dot.edge('data', 'dev', label='Data Ready')
dot.edge('dev', 'test', label='System Built')
dot.edge('test', 'end', label='Tests Passed')

# Render the flowchart
dot.render('eigenguard_one_semester_flowchart', view=True)

print("Flowchart generated as 'eigenguard_one_semester_flowchart.png'")