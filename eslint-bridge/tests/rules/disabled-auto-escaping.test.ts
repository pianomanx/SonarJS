/*
 * SonarQube JavaScript Plugin
 * Copyright (C) 2011-2020 SonarSource SA
 * mailto:info AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
import { rule } from 'rules/disabled-auto-escaping';
import { RuleTesterTs } from '../RuleTesterTs';

const ruleTester = new RuleTesterTs();

const handlebarsCases = {
  valid: [
    {
      code: `
      const Handlebars = require("handlebars");
      var options = {
        noEscape: false // Compliant
      };
      var source = "<p>attack {{name}}</p>";
      var template = Handlebars.compile(source, options); // Compliant
            `,
    },
    {
      code: `
      const Handlebars = require("handlebars");
      if (x) {
        var options = {
          noEscape: true
        };
      } else {
        var options = {
          noEscape: false
        };
      }
      var source = "<p>attack {{name}}</p>";
      var template = Handlebars.compile(source, options); // Compliant
            `,
    },
    {
      code: `
      const Handlebars = require("handlebars");
      var source = "<p>attack {{name}}</p>";
      var template = Handlebars.compile(source); // Compliant by default noEscape is set to false
            `,
    },
  ],
  invalid: [
    {
      code: `
      const Handlebars = require("handlebars");
      var options = {
        noEscape: true // Sensitive
      };
      var source = "<p>attack {{name}}</p>";
      var template = Handlebars.compile(source, options); // Sensitive
            `,
      errors: 1,
    },
  ],
};

const markdownCases = {
  valid: [
    {
      code: `
      var md = require('markdown-it')({
        html: false
      });  // Compliant
      var result = md.render('# <b>attack</b>');
      console.log(result); 
            `,
    },
    {
      code: `
      var md = require('markdown-it')(); // Compliant by default html is set to false
      var result = md.render('# <b>attack</b>');
      console.log(result);
            `,
    },
  ],
  invalid: [
    {
      code: `
      var md = require('markdown-it')({
        html: true // Sensitive
      });
      var result = md.render('# <b>attack</b>');
      console.log(result);
            `,
      errors: 1,
    },
  ],
};

const kramedCases = {
  valid: [
    {
      code: `
      var kramed = require('kramed');
      var options = {
        renderer: new kramed.Renderer({
          sanitize: true  // Compliant
        })
      };
      console.log(kramed('Attack [xss?](javascript:alert("xss")).', options)); // Compliant 
            `,
    },
    {
      code: `
      var options = {
        renderer: new Unknown({
          sanitize: true
        })
      };
            `,
    },
  ],
  invalid: [
    {
      code: `
      var kramed = require('kramed');
      var options = {
        renderer: new kramed.Renderer({
          sanitize: false // Sensitive
        })
      };
      console.log(kramed('Attack1 [xss?](javascript:alert("xss")).', options));
      console.log(kramed('Attack2 [xss?](javascript:alert("xss")).')); // Without option it's not sanitized, but likely if the user doesn't passed option, "it's a basic rendering"
            `,
      errors: 1,
    },
  ],
};

const markedCases = {
  valid: [
    {
      code: `
      const marked = require('marked');
      marked.setOptions({
        renderer: new marked.Renderer(),
        sanitize: true // Compliant
      });
      console.log(marked("# test <b>attack/b>"));  
            `,
    },
    {
      code: `
      const marked = require('marked');
      marked.setOptions({
        renderer: new marked.Renderer()
      }); // Compliant by default sanitize is set to true
      console.log(marked("# test <b>attack/b>"));  
            `,
    },
  ],
  invalid: [
    {
      code: `
      const marked = require('marked');
      marked.setOptions({
        renderer: new marked.Renderer(),
        sanitize: false // Sensitive
      });
      console.log(marked("# test <b>attack/b>"));  
            `,
      errors: 1,
    },
  ],
};

const mustatcheCases = {
  valid: [
    {
      code: `
      const Mustache = require("mustache");   
      function renderHello() {
        var inputName = "<b>Luke</b>";
        var template = document.getElementById('template').innerHTML;
        var rendered = Mustache.render(template, { name: inputName }); // Compliant
        document.getElementById('target').innerHTML = rendered;
      }
            `,
    },
    {
      code: `
      const Mustache = require("mustache");
      function renderHello() {
        var inputName = "<b>Luke</b>";
        var template = document.getElementById('template').innerHTML;
        Mustache.escape = unknown();
        var rendered = Mustache.render(template, { name: inputName });
        document.getElementById('target').innerHTML = rendered; 
      }
            `,
    },
    {
      code: `
      const Mustache = require("mustache");
      function renderHello() {
        var inputName = "<b>Luke</b>";
        var template = document.getElementById('template').innerHTML;
        Mustache.escape = function(text) {
          if(text.includes("<script>")) {
              return "blocked";
           }
          return text;
        };
        var rendered = Mustache.render(template, { name: inputName });
        document.getElementById('target').innerHTML = rendered; 
      }
            `,
    },
    {
      code: `
      const Mustache = require("mustache");
      function renderHello() {
        var inputName = "<b>Luke</b>";
        var template = document.getElementById('template').innerHTML;
        Mustache.escape = function(text, other) {return text;};
        var rendered = Mustache.render(template, { name: inputName });
        document.getElementById('target').innerHTML = rendered; 
      }
            `,
    },
    {
      code: `
      const Mustache = require("mustache");
      function renderHello() {
        var inputName = "<b>Luke</b>";
        var template = document.getElementById('template').innerHTML;
        Mustache.escape = function(text) {return sanitize(text);};
        var rendered = Mustache.render(template, { name: inputName });
        document.getElementById('target').innerHTML = rendered; 
      }
            `,
    },
    {
      code: `
      const Mustache = require("mustache");
      function renderHello() {
        var inputName = "<b>Luke</b>";
        var template = document.getElementById('template').innerHTML;
        Mustache.escape = text, other => text;
        var rendered = Mustache.render(template, { name: inputName });
        document.getElementById('target').innerHTML = rendered; 
      }
            `,
      errors: 1,
    },
  ],
  invalid: [
    {
      code: `
      const Mustache = require("mustache");
      function renderHello() {
        var inputName = "<b>Luke</b>";
        var template = document.getElementById('template').innerHTML;
        Mustache.escape = function(text) {return text;}; // Sensitive
        var rendered = Mustache.render(template, { name: inputName });
        document.getElementById('target').innerHTML = rendered; 
      }
            `,
      errors: 1,
    },
    {
      code: `
      const Mustache = require("mustache");
      function invalidSanitizer(text) {
        return text;
      }
      function renderHello() {
        var inputName = "<b>Luke</b>";
        var template = document.getElementById('template').innerHTML;
        Mustache.escape = invalidSanitizer; // Sensitive
        var rendered = Mustache.render(template, { name: inputName });
        document.getElementById('target').innerHTML = rendered; 
      }
            `,
      errors: 1,
    },
    {
      code: `
      const Mustache = require("mustache");
      function renderHello() {
        var inputName = "<b>Luke</b>";
        var template = document.getElementById('template').innerHTML;
        Mustache.escape = text => text;
        var rendered = Mustache.render(template, { name: inputName });
        document.getElementById('target').innerHTML = rendered; 
      }
            `,
      errors: 1,
    },
    {
      code: `
      const Mustache = require("mustache");
      function renderHello() {
        var inputName = "<b>Luke</b>";
        const invalidSanitizer = text => text;
        var template = document.getElementById('template').innerHTML;
        Mustache.escape = invalidSanitizer;
        var rendered = Mustache.render(template, { name: inputName });
        document.getElementById('target').innerHTML = rendered; 
      }
            `,
      errors: 1,
    },
    {
      code: `
      const Mustache = require("mustache");
      function renderHello() {
        var inputName = "<b>Luke</b>";
        const invalidSanitizer = function(text) {return text;};
        var template = document.getElementById('template').innerHTML;
        Mustache.escape = invalidSanitizer;
        var rendered = Mustache.render(template, { name: inputName });
        document.getElementById('target').innerHTML = rendered; 
      }
            `,
      errors: 1,
    },
  ],
};

ruleTester.run('Handlebars', rule, handlebarsCases);
ruleTester.run('markdown-it', rule, markdownCases);
ruleTester.run('kramed', rule, kramedCases);
ruleTester.run('marked', rule, markedCases);
ruleTester.run('mustache', rule, mustatcheCases);
