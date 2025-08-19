import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { logger } from '../utils/logger.js';

export function setupExamplePrompts(server: McpServer): void {
  logger.info('Setting up example prompts');
  
  // Data Analysis Prompts
  server.prompt(
    'analyze-dataset',
    'Generate prompts for comprehensive data analysis',
    () => ({
      messages: [
        {
          role: 'user',
          content: {
            type: 'text',
            text: `Please analyze the provided dataset and provide:

1. Data quality assessment
2. Key findings and insights  
3. Statistical analysis
4. Visualization recommendations
5. Business recommendations
6. Next steps for deeper analysis

Format your response with clear headings and bullet points for actionability.

Include trends analysis, correlation identification, outlier detection, and comprehensive summary statistics.`
          }
        }
      ]
    })
  );

  // Code Generation Prompts
  server.prompt(
    'generate-code',
    'Generate prompts for code creation with best practices',
    () => ({
      messages: [
        {
          role: 'user',
          content: {
            type: 'text',
            text: `Generate high-quality, production-ready code based on the provided requirements.

Please provide:
1. Clean, well-commented code following language best practices
2. Proper error handling and input validation
3. Type definitions (if applicable)
4. Usage examples and comprehensive documentation
5. Performance and security considerations
6. Unit and integration tests

Architecture patterns to consider:
- Modular design with clear separation of concerns
- SOLID principles and design patterns
- Scalable and maintainable structure
- Comprehensive error handling

Include specific implementation details for:
- API endpoints with proper routing and middleware
- CLI tools with argument parsing and help systems
- Libraries with clear interfaces and examples
- Algorithms with complexity analysis
- Full applications with complete architecture`
          }
        }
      ]
    })
  );

  // Content Creation Prompts  
  server.prompt(
    'create-content',
    'Generate prompts for various content creation tasks',
    () => ({
      messages: [
        {
          role: 'user',
          content: {
            type: 'text',
            text: `Create high-quality content based on the provided topic and specifications.

Content Types to Support:
- Blog posts with compelling headlines and structured flow
- Technical documentation with examples and step-by-step instructions  
- Professional emails with clear subject lines and call-to-actions
- Presentation outlines with slide titles and speaker notes
- Social media content optimized for engagement
- Marketing copy with persuasive headlines and strong CTAs

Please ensure the content:
1. Captures attention from the first line
2. Provides clear value to the target audience
3. Maintains appropriate tone throughout
4. Includes relevant examples or case studies
5. Has proper structure with headings and subheadings
6. Ends with actionable next steps or strong conclusion
7. Is optimized for the specified content format

Consider audience needs, tone requirements, length specifications, and primary purpose (inform, persuade, educate, entertain, or convert).`
          }
        }
      ]
    })
  );

  // Technical Review Prompts
  server.prompt(
    'technical-review',
    'Generate prompts for comprehensive technical reviews',
    () => ({
      messages: [
        {
          role: 'user',
          content: {
            type: 'text',
            text: `Perform a comprehensive technical review of the provided system, code, or architecture.

Review Types:
- Code reviews focusing on best practices, potential bugs, and optimization
- Architecture reviews examining design patterns, scalability, and technical debt
- Security audits identifying vulnerabilities and attack vectors
- Performance analysis examining bottlenecks and optimization opportunities

Please provide:
1. Executive Summary
2. Key Findings (organized by severity)
3. Detailed Analysis for focus areas
4. Risk Assessment and impact evaluation
5. Prioritized Recommendations
6. Implementation Timeline
7. Success Metrics and monitoring

Format findings with severity indicators:
- 🔴 Critical issues requiring immediate attention
- 🟡 Important improvements needed
- 🟢 Minor optimizations and best practices

Include specific examples, code snippets, or architectural diagrams where helpful.
Focus on security, performance, maintainability, and scalability considerations.`
          }
        }
      ]
    })
  );

  // Learning Plan Prompts
  server.prompt(
    'create-learning-plan',
    'Generate personalized learning plans and educational content',
    () => ({
      messages: [
        {
          role: 'user',
          content: {
            type: 'text',
            text: `Create a comprehensive, personalized learning plan for the specified topic and learner profile.

Please provide:
1. Learning Path Overview (phases and milestones)
2. Week-by-Week Curriculum
3. Required Resources and Materials
4. Practical Projects and Exercises
5. Assessment Methods and Checkpoints
6. Common Challenges and How to Overcome Them
7. Next Steps After Completion

Structure the plan with:
- Clear learning objectives for each phase
- Specific activities and time allocations
- Progress tracking methods
- Flexibility for different learning paces
- Real-world application opportunities

Learning Approaches to Consider:
- Visual learners: diagrams, charts, infographics, and visual examples
- Hands-on learners: practical exercises, projects, and interactive learning
- Theoretical learners: concepts, principles, and deep understanding
- Mixed approach: combining visual aids, practical exercises, and theoretical foundations

Adapt content complexity based on learner's current skill level (beginner, intermediate, advanced, expert) and available time commitment.`
          }
        }
      ]
    })
  );

  // Business Strategy Prompts
  server.prompt(
    'business-strategy',
    'Generate prompts for business analysis and strategic planning',
    () => ({
      messages: [
        {
          role: 'user',
          content: {
            type: 'text',
            text: `Conduct comprehensive business analysis and strategic planning based on the provided context.

Analysis Types:
- Market analysis using TAM/SAM/SOM framework and market trends
- Competitive landscape analysis with positioning maps and strategy assessment
- SWOT analysis examining internal strengths/weaknesses and external opportunities/threats
- Business plan development covering value proposition and financial projections
- Growth strategy analysis with expansion opportunities and scaling challenges

Please provide:
1. Executive Summary
2. Current Situation Assessment
3. Market Environment Analysis
4. Strategic Options Evaluation
5. Recommended Strategy
6. Implementation Roadmap
7. Risk Assessment and Mitigation
8. Success Metrics and KPIs
9. Resource Requirements
10. Next Steps and Decision Points

Structure analysis with:
- Data-driven insights and market research
- Clear recommendations with rationale
- Actionable implementation steps
- Quantifiable success metrics
- Timeline considerations for planning horizon

Company Stage Considerations:
- Startup: product-market fit, initial traction, sustainable unit economics
- Growth: scaling operations, market expansion, competitive positioning  
- Mature: market consolidation, diversification, operational efficiency
- Enterprise: market leadership, innovation, digital transformation`
          }
        }
      ]
    })
  );

  logger.info('Example prompts setup completed - 6 prompt templates registered');
}