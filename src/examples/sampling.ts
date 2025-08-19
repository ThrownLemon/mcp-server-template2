import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { logger } from '../utils/logger.js';

export function setupSampling(server: McpServer): void {
  logger.info('Setting up sampling capabilities');
  
  // Tool for text summarization using LLM sampling
  server.tool(
    'llm-summarize',
    'Summarize any text using LLM sampling with configurable length',
    {
      text: {
        type: 'string',
        description: 'Text to summarize'
      },
      maxLength: {
        type: 'number', 
        description: 'Maximum length of summary (default: 200 words)',
        default: 200
      }
    },
    async ({ text, maxLength = 200 }) => {
      try {
        logger.info('Processing LLM summarization request', { textLength: text.length, maxLength });
        
        // Create sampling request to LLM
        const response = await server.server.createMessage({
          messages: [
            {
              role: 'user',
              content: {
                type: 'text',
                text: `Please summarize the following text in approximately ${maxLength} words or less. Be concise and capture the key points:\n\n${text}`
              }
            }
          ],
          maxTokens: Math.min(maxLength * 2, 1000), // Estimate tokens from words
          temperature: 0.3 // Lower temperature for more focused summaries
        });

        const summaryText = response.content.type === 'text' 
          ? response.content.text 
          : 'Unable to generate summary';

        logger.info('LLM summarization completed', { summaryLength: summaryText.length });
        
        return {
          content: [
            {
              type: 'text',
              text: summaryText
            }
          ]
        };
      } catch (error) {
        logger.error('Error in LLM summarization', error);
        return {
          content: [
            {
              type: 'text',
              text: `Error generating summary: ${error instanceof Error ? error.message : 'Unknown error'}`
            }
          ]
        };
      }
    }
  );

  // Tool for recursive content analysis using multiple LLM calls
  server.tool(
    'recursive-analysis',
    'Perform recursive content analysis using multiple LLM interactions',
    {
      content: {
        type: 'string',
        description: 'Content to analyze'
      },
      analysisType: {
        type: 'string',
        description: 'Type of analysis: sentiment, topics, structure, or comprehensive',
        enum: ['sentiment', 'topics', 'structure', 'comprehensive']
      },
      depth: {
        type: 'number',
        description: 'Analysis depth level (1-3, default: 2)',
        default: 2
      }
    },
    async ({ content, analysisType, depth = 2 }) => {
      try {
        logger.info('Starting recursive analysis', { analysisType, depth, contentLength: content.length });
        
        const results = [];
        
        // Step 1: Initial analysis
        const initialPrompt = getAnalysisPrompt(analysisType, content, 1);
        const initialResponse = await server.server.createMessage({
          messages: [
            {
              role: 'user',
              content: {
                type: 'text',
                text: initialPrompt
              }
            }
          ],
          maxTokens: 500,
          temperature: 0.4
        });

        const initialAnalysis = initialResponse.content.type === 'text' 
          ? initialResponse.content.text 
          : 'Initial analysis failed';
        
        results.push({
          step: 1,
          type: 'initial_analysis',
          content: initialAnalysis
        });

        // Step 2+: Recursive deepening based on depth
        if (depth > 1) {
          for (let step = 2; step <= depth; step++) {
            const deeperPrompt = `Based on this previous analysis:\n\n${initialAnalysis}\n\nProvide deeper insights and identify specific patterns, examples, or implications. Focus on details that weren't covered in the initial analysis.`;
            
            const deeperResponse = await server.server.createMessage({
              messages: [
                {
                  role: 'user',
                  content: {
                    type: 'text',
                    text: deeperPrompt
                  }
                }
              ],
              maxTokens: 400,
              temperature: 0.5
            });

            const deeperAnalysis = deeperResponse.content.type === 'text'
              ? deeperResponse.content.text
              : `Step ${step} analysis failed`;

            results.push({
              step,
              type: 'deeper_analysis',
              content: deeperAnalysis
            });
          }
        }

        // Final synthesis if multiple steps
        if (results.length > 1) {
          const synthesisPrompt = `Synthesize these multiple analysis steps into a coherent final analysis:\n\n${results.map(r => `Step ${r.step}: ${r.content}`).join('\n\n')}`;
          
          const synthesisResponse = await server.server.createMessage({
            messages: [
              {
                role: 'user',
                content: {
                  type: 'text',
                  text: synthesisPrompt
                }
              }
            ],
            maxTokens: 600,
            temperature: 0.3
          });

          const synthesis = synthesisResponse.content.type === 'text'
            ? synthesisResponse.content.text
            : 'Synthesis failed';

          results.push({
            step: results.length + 1,
            type: 'synthesis',
            content: synthesis
          });
        }

        logger.info('Recursive analysis completed', { totalSteps: results.length });

        const formattedResults = results.map(r => 
          `**${r.type.toUpperCase()} (Step ${r.step})**\n${r.content}`
        ).join('\n\n---\n\n');

        return {
          content: [
            {
              type: 'text',
              text: formattedResults
            }
          ]
        };
      } catch (error) {
        logger.error('Error in recursive analysis', error);
        return {
          content: [
            {
              type: 'text', 
              text: `Error in recursive analysis: ${error instanceof Error ? error.message : 'Unknown error'}`
            }
          ]
        };
      }
    }
  );

  // Tool for agentic workflow orchestration
  server.tool(
    'agentic-workflow',
    'Execute an agentic workflow with multiple LLM interactions and decision points',
    {
      task: {
        type: 'string',
        description: 'Description of the task to execute'
      },
      context: {
        type: 'string',
        description: 'Additional context or constraints for the task'
      },
      maxSteps: {
        type: 'number',
        description: 'Maximum number of workflow steps (default: 5)',
        default: 5
      }
    },
    async ({ task, context, maxSteps = 5 }) => {
      try {
        logger.info('Starting agentic workflow', { task, maxSteps });
        
        const workflowSteps = [];
        let currentStep = 1;
        let shouldContinue = true;
        let workflowState = `Task: ${task}\nContext: ${context}`;

        while (shouldContinue && currentStep <= maxSteps) {
          // Planning step
          const planningPrompt = `You are an AI agent executing a workflow. Current state:\n\n${workflowState}\n\nStep ${currentStep}: What should be the next action? Provide a specific, actionable step. If the task is complete, respond with "WORKFLOW_COMPLETE".`;
          
          const planningResponse = await server.server.createMessage({
            messages: [
              {
                role: 'user',
                content: {
                  type: 'text',
                  text: planningPrompt
                }
              }
            ],
            maxTokens: 300,
            temperature: 0.4
          });

          const nextAction = planningResponse.content.type === 'text'
            ? planningResponse.content.text
            : 'Planning failed';

          if (nextAction.includes('WORKFLOW_COMPLETE')) {
            shouldContinue = false;
            workflowSteps.push({
              step: currentStep,
              type: 'completion',
              action: 'Workflow completed successfully',
              result: nextAction.replace('WORKFLOW_COMPLETE', '').trim()
            });
            break;
          }

          // Execution step
          const executionPrompt = `Execute this action: "${nextAction}"\n\nCurrent workflow state: ${workflowState}\n\nProvide the result of executing this action and any new information discovered.`;
          
          const executionResponse = await server.server.createMessage({
            messages: [
              {
                role: 'user',
                content: {
                  type: 'text',
                  text: executionPrompt
                }
              }
            ],
            maxTokens: 400,
            temperature: 0.3
          });

          const executionResult = executionResponse.content.type === 'text'
            ? executionResponse.content.text
            : 'Execution failed';

          workflowSteps.push({
            step: currentStep,
            type: 'action',
            action: nextAction,
            result: executionResult
          });

          // Update workflow state
          workflowState += `\n\nStep ${currentStep} Action: ${nextAction}\nResult: ${executionResult}`;
          currentStep++;
        }

        logger.info('Agentic workflow completed', { totalSteps: workflowSteps.length });

        const formattedWorkflow = workflowSteps.map(step => 
          `**STEP ${step.step} (${step.type.toUpperCase()})**\n` +
          `Action: ${step.action}\n` +
          `Result: ${step.result}`
        ).join('\n\n---\n\n');

        return {
          content: [
            {
              type: 'text',
              text: `**AGENTIC WORKFLOW EXECUTION**\n\nTask: ${task}\n\n${formattedWorkflow}`
            }
          ]
        };
      } catch (error) {
        logger.error('Error in agentic workflow', error);
        return {
          content: [
            {
              type: 'text',
              text: `Error in agentic workflow: ${error instanceof Error ? error.message : 'Unknown error'}`
            }
          ]
        };
      }
    }
  );

  logger.info('Sampling capabilities setup completed');
}

function getAnalysisPrompt(analysisType: string, content: string, step: number): string {
  const prompts = {
    sentiment: `Analyze the sentiment and emotional tone of the following content. Identify positive, negative, and neutral elements:\n\n${content}`,
    topics: `Identify and analyze the main topics, themes, and key concepts in the following content:\n\n${content}`,
    structure: `Analyze the structure, organization, and logical flow of the following content:\n\n${content}`,
    comprehensive: `Perform a comprehensive analysis covering sentiment, topics, structure, and any notable patterns in the following content:\n\n${content}`
  };
  
  return prompts[analysisType as keyof typeof prompts] || prompts.comprehensive;
}